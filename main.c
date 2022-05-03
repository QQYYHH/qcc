/*
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:48:11
 * @LastEditTime: 2022-05-03 20:07:55
 * @LastEditors: QQYYHH
 * @Description: 主函数
 * @FilePath: /pwn/qcc/main.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "qcc.h"

#define MAX_ARGS 6
// 最大表达式的数量
#define EXPR_LEN 100

#define swap(a, b)         \
    {                      \
        typeof(a) tmp = a; \
        a = b;             \
        b = tmp;           \
    }

// 增加 AST节点类型的枚举定义
enum
{
    AST_LITERAL, // 字面量，包括常量、字符、字符串
    AST_VAR,
    AST_FUNCALL,
    AST_DECL,  // declaration
    AST_ADDR,  // 代表 & 单目运算
    AST_DEREF, // 代表 * 单目运算
};

// 不同的C类型
enum
{
    CTYPE_VOID,
    CTYPE_INT,
    CTYPE_CHAR,
    CTYPE_STR,
    CTYPE_PTR, // 指针类型
};

typedef struct Ctype
{
    int type;
    /**
     * 如果是非指针，该字段为NULL
     * 如果是指针，则为指向的变量类型
     */
    struct Ctype *ptr;
} Ctype;

// 增加AST节点定义
typedef struct Ast
{
    int type;
    // 子树代表的C类型
    Ctype *ctype;
    // 匿名联合，对应不同AST类型
    union
    {
        // Integer
        int ival;
        // Char
        char c;
        // String
        struct
        {
            char *sval;
            // 字符串在数据段保存的位置
            int sid;
            struct Ast *snext;
        };
        // Variable
        struct
        {
            char *vname;
            // 用于控制栈中生成的局部变量的位置
            int vpos;
            struct Ast *vnext;
        };
        // Binary operation + - * / =
        struct
        {
            struct Ast *left;
            struct Ast *right;
        };
        // Unary operator，单目运算
        struct
        {
            // 单目运算操作数
            struct Ast *operand;
        };

        // Function call
        struct
        {
            char *fname;
            int nargs;
            struct Ast **args;
        };
        // Declaration
        struct
        {
            struct Ast *decl_var;
            struct Ast *decl_init;
        };
    };
} Ast;

// 全局 变量链表、字符串链表
static Ast *vars = NULL;
static Ast *strings = NULL;
// x64下函数前6个实参会依次放入下列寄存器
static char *REGS[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};

static Ctype *ctype_int = &(Ctype){CTYPE_INT, NULL};
static Ctype *ctype_char = &(Ctype){CTYPE_CHAR, NULL};
static Ctype *ctype_str = &(Ctype){CTYPE_STR, NULL};

static void emit_expr(Ast *ast);
// 必要的递归下降语法分析函数的定义
static Ast *parse_expr(int prev_priority);
static char *ast_to_string(Ast *ast);
static Ast *parse_prim(void);

// ===================== make AST ====================

/**
 * 单目运算树
 */
static Ast *make_ast_uop(char type, Ctype *ctype, Ast *operand)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = type;
    r->ctype = ctype;
    r->operand = operand;
    return r;
}

/**
 * 二元操作树，表达式抽象语法树
 */
static Ast *make_ast_binop(int type, Ctype *ctype, Ast *left, Ast *right)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = type;
    r->ctype = ctype;
    r->left = left;
    r->right = right;
    return r;
}

static Ast *make_ast_char(char c)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_LITERAL;
    r->ctype = ctype_char;
    r->c = c;
    return r;
}

static Ast *make_ast_int(int val)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_LITERAL;
    r->ctype = ctype_int;
    r->ival = val;
    return r;
}

static Ast *make_ast_str(char *str)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_LITERAL;
    r->ctype = ctype_str;
    r->sval = str;
    r->snext = strings;
    r->sid = strings ? strings->sid + 1 : 0;
    strings = r;
    return r;
}

static Ast *make_ast_var(Ctype *ctype, char *vname)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_VAR;
    r->ctype = ctype;
    r->vname = vname;
    r->vpos = vars ? vars->vpos + 1 : 1;
    r->vnext = vars;
    vars = r;
    return r;
}

static Ast *find_var(char *name)
{
    for (Ast *v = vars; v; v = v->vnext)
    {
        if (!strcmp(name, v->vname))
            return v;
    }
    return NULL;
}

static Ast *make_ast_funcall(char *fname, int nargs, Ast **args)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_FUNCALL;
    // 默认函数返回类型为 int
    r->ctype = ctype_int;
    r->fname = fname;
    r->nargs = nargs;
    r->args = args;
    return r;
}

static bool is_right_assoc(char op)
{
    return op == '=';
}

static Ast *make_ast_decl(Ast *var, Ast *init)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_DECL;
    r->ctype = NULL;
    r->decl_var = var;
    r->decl_init = init;
    return r;
}

// ptr_ctype是指针所指向变量的 ctype
static Ctype *make_ptr_type(Ctype *ptr_ctype)
{
    Ctype *r = malloc(sizeof(Ctype));
    r->type = CTYPE_PTR;
    r->ptr = ptr_ctype;
    return r;
}

static int priority(char op)
{
    switch (op)
    {
    case '=':
        return 1;
    case '+':
    case '-':
        return 2;
    case '*':
    case '/':
        return 3;
    default:
        return -1;
    }
}

// ===================== parse ====================

/**
 * 类型检查，推断当前二元表达式树的类型
 * 根据左右子树的类型推断
 */
static Ctype *result_type_int(jmp_buf *jmpbuf, Ctype *a, Ctype *b)
{
    /**
     * 如果是指针，则参与运算的两个子树的类型都必须是指针【暂时这么规定】
     * 进而继续检查指针所指向变量的类型是否合规
     */
    if (a->type == CTYPE_PTR)
    {
        if (b->type != CTYPE_PTR)
            goto err;
        Ctype *r = malloc(sizeof(Ctype));
        r->type = CTYPE_PTR;
        r->ptr = result_type_int(jmpbuf, a->ptr, b->ptr);
        return r;
    }
    if (a->type > b->type)
        swap(a, b);

    switch (a->type)
    {
    /* void不能和任何类型发生运算 */
    case CTYPE_VOID:
        goto err;
    /* int op [int, char] -> int */
    /* int op str -> error */
    case CTYPE_INT:
        switch (b->type)
        {
        case CTYPE_INT:
        case CTYPE_CHAR:
            return ctype_int;
        case CTYPE_STR:
            goto err;
        }
        error("internal error");
    /* char op char -> int */
    /* char op str -> error */
    case CTYPE_CHAR:
        switch (b->type)
        {
        case CTYPE_CHAR:
            return ctype_int;
        case CTYPE_STR:
            goto err;
        }
        error("internal error");
    /* str 不能和任何类型发生运算 */
    case CTYPE_STR:
        goto err;
    default:
        error("internal error");
    }
err:
    longjmp(*jmpbuf, 1);
}

static Ctype *result_type(char op, Ast *a, Ast *b)
{
    jmp_buf jmpbuf;
    if (setjmp(jmpbuf) == 0)
        return result_type_int(&jmpbuf, a->ctype, b->ctype);
    error("incompatible operands: %c: <%s> and <%s>",
          op, ast_to_string(a), ast_to_string(b));
}

// 确保左子节点ast是 变量类型
static void ensure_lvalue(Ast *ast)
{
    if (ast->type != AST_VAR)
        error("Variable expected, but got %s", ast_to_string(ast));
}

/**
 * unary_expr := &|* unary_expr
 * unary_expr := prim
 */
static Ast *parse_unary_expr(void)
{
    Token *tok = read_token();
    // 取地址，也可以对指针变量取地址
    // 暂不支持多重& 例如 &&&a
    if (is_punct(tok, '&'))
    {
        Ast *operand = parse_unary_expr();
        ensure_lvalue(operand);
        return make_ast_uop(AST_ADDR, make_ptr_type(operand->ctype), operand);
    }
    // 访存【解引用】 deref
    // 支持多重解引用 例如：***a
    if (is_punct(tok, '*'))
    {
        Ast *operand = parse_unary_expr();
        if (operand->ctype->type != CTYPE_PTR)
            error("pointer type expected, but got %s", ast_to_string(operand));
        return make_ast_uop(AST_DEREF, operand->ctype->ptr, operand);
    }
    unget_token(tok);
    return parse_prim();
}

/**
 * 函数参数
 * func_args := expr2 | expr2, func_args | NULL
 */
static Ast *parse_func_args(char *fname)
{
    Ast **args = malloc(sizeof(Ast *) * (MAX_ARGS + 1));
    int i = 0, nargs = 0;
    for (; i < MAX_ARGS + 1; i++)
    {
        if (i == MAX_ARGS)
            error("Too many arguments: %s", fname);
        Token *tok = read_token();
        if (is_punct(tok, ')'))
            break;
        unget_token(tok);
        args[i] = parse_expr(0);
        nargs++;
        tok = read_token();
        if (is_punct(tok, ')'))
            break;
        if (is_punct(tok, ','))
        {
            tok = read_token();
            if (is_punct(tok, ')'))
                error("Can not find next arg");
            unget_token(tok);
        }
        else
            error("Unexpected token: '%s'", token_to_string(tok));
    }
    return make_ast_funcall(fname, nargs, args);
}

/**
 * 常量或者函数
 * ident_or_func := identifier | function
 * function := identifer ( func_args )
 */
static Ast *parse_ident_or_func(char *name)
{
    Token *tok = read_token();
    // funcall
    if (is_punct(tok, '('))
        return parse_func_args(name);
    // identifier
    unget_token(tok);
    Ast *v = find_var(name);
    // must declaration before using.
    if (!v)
        error("Undefined varaible: %s", name);
    return v;
}

/**
 * 基本单元，可以是整数常量、单字符、字符串常量、标识符 或者为空
 * prim := number | char | string | variable | funcall | NULL
 */
static Ast *parse_prim(void)
{
    Token *tok = read_token();
    if (!tok)
        return NULL;
    switch (tok->type)
    {
    case TTYPE_IDENT:
        return parse_ident_or_func(tok->sval);
    case TTYPE_INT:
        return make_ast_int(tok->ival);
    case TTYPE_CHAR:
        return make_ast_char(tok->c);
    case TTYPE_STRING:
        return make_ast_str(tok->sval);
    case TTYPE_PUNCT:
        error("unexpected character: '%c'", tok->punct);
    default:
        error("internal error: unknown token type: %d", tok->type);
    }
}

/**
 * 混合运算表达式 或 赋值语句
 * prev_priority 代表上一个符号的优先级
 * expr := + - * / = 混合运算以及赋值语句
 *
 * expr := unary_expr cal expr | unary_expr
 * cal := + - * / =
 */
static Ast *parse_expr(int prev_priority)
{
    Ast *ast = parse_unary_expr();
    if (!ast)
        return NULL;
    for (;;)
    {
        Token *tok = read_token();
        if (tok == NULL)
            return ast;
        // 这里存在一些问题，应该判断tok->punct是否为4则运算符号
        // 后面emit的时候检查是否为 运算符
        int prio = priority(tok->punct);
        /* 赋值语句中 = 的优先级比较特殊，相同符号前面的优先级 < 后面；对于+ - * / 来说，相同符号前面的优先级 > 后面 */
        /* 因此 优先级相等的这种情况要单独拿出来讨论 */
        int is_equal = is_punct(tok, '=');
        if (prio <= prev_priority && !is_equal)
        {
            unget_token(tok);
            return ast;
        }
        // 如果是赋值语句，确保左子节点的类型是 AST_VAR
        if (is_equal)
            ensure_lvalue(ast);
        Ast *right = parse_expr(prio);
        Ctype *ctype = result_type(tok->punct, ast, right);
        ast = make_ast_binop(tok->punct, ctype, ast, right);
    }
}

static Ctype *get_ctype(Token *tok)
{
    if (tok->type != TTYPE_IDENT)
        return NULL;
    if (!strcmp(tok->sval, "int"))
        return ctype_int;
    if (!strcmp(tok->sval, "char"))
        return ctype_char;
    if (!strcmp(tok->sval, "string"))
        return ctype_str;
    return NULL;
}

static bool is_type_keyword(Token *tok)
{
    return get_ctype(tok) != NULL;
}
static void expect(char punct)
{
    Token *tok = read_token();
    if (!is_punct(tok, punct))
        error("'%c' expected, but got %s", punct, token_to_string(tok));
}

/**
 * 声明
 * decl := ctype identifer = init_value
 * 其实 声明 本质上来讲还是赋值操作，只不过要考虑类型
 * TODO 逗号分隔变量的声明 比如 int a = 1, b = 2;
 */
static Ast *parse_decl()
{
    Ctype *ctype = get_ctype(read_token());
    Token *tok;
    // 判断是否是指针类型的变量
    // 也可能是多维指针变量
    for (;;)
    {
        tok = read_token();
        if (!tok)
            error("Unexpected terminated..");
        if (!is_punct(tok, '*'))
            break;
        ctype = make_ptr_type(ctype);
    }

    if (tok->type != TTYPE_IDENT)
        error("Identifier expected, but got %s", token_to_string(tok));
    Ast *var = make_ast_var(ctype, tok->sval);
    expect('=');
    Ast *init = parse_expr(0);
    return make_ast_decl(var, init);
}

/**
 * decl or stmt
 * 目前来讲，stmt就是表达式
 */
static Ast *parse_decl_or_stmt()
{
    // 仅作比较，不将token从缓冲区删除
    Token *tok = peek_token();
    if (!tok)
        return NULL;
    Ast *ast = is_type_keyword(tok) ? parse_decl() : parse_expr(0);
    expect(';');
    return ast;
}

// ===================== emit ====================

static char *quote(char *p)
{
    String *s = make_string();
    while (*p)
    {
        if (*p == '\"' || *p == '\\')
            string_append(s, '\\');
        string_append(s, *p);
        p++;
    }
    return get_cstring(s);
}

static void emit_data_section()
{
    if (!strings)
        return;
    printf("\t.data\n");
    for (Ast *p = strings; p; p = p->snext)
    {
        printf(".s%d:\n\t", p->sid);
        printf(".string \"%s\"\n", quote(p->sval));
    }
}

static void emit_assign(Ast *var, Ast *value)
{
    emit_expr(value);
    // 如果赋值号左边不是 变量，则抛出异常
    if (var->type != AST_VAR)
        error("Symbol expected");
    // 假设类型占用 8字节
    // TODO 考虑变量类型
    printf("mov %%rax, -%d(%%rbp)\n\t", var->vpos * 8);
}

static void emit_binop(Ast *ast)
{
    // 如果是赋值语句
    if (ast->type == '=')
    {
        emit_assign(ast->left, ast->right);
        return;
    }
    // 如果是计算表达式
    char *op;
    switch (ast->type)
    {
    case '+':
        op = "add";
        break;
    case '-':
        op = "sub";
        break;
    case '*':
        op = "imul";
        break;
    case '/':
        op = "idiv";
        break;
    default:
        error("invalid operator '%c'", ast->type);
    }
    emit_expr(ast->left);
    printf("push %%rax\n\t");
    emit_expr(ast->right);
    printf("mov %%rax, %%rbx\n\t");
    printf("pop %%rax\n\t");
    if (ast->type == '/')
    {
        printf("mov $0, %%rdx\n\t");
        printf("idiv %%rbx\n\t");
    }
    else
    {
        printf("%s %%rbx, %%rax\n\t", op);
    }
}

static void emit_expr(Ast *ast)
{
    switch (ast->type)
    {
    case AST_LITERAL:
        switch (ast->ctype->type)
        {
        case CTYPE_INT:
            printf("mov $%d, %%rax\n\t", ast->ival);
            break;
        case CTYPE_CHAR:
            printf("mov $%d, %%rax\n\t", ast->c);
            break;
        case CTYPE_STR:
            // x64特有的rip相对寻址，.s是数据段中字符串的标识符
            // 比如数据段中有.s0, .s1, .s2等，分别代表不同的字符串
            printf("lea .s%d(%%rip), %%rax\n\t", ast->sid);
            break;
        default:
            error("internal error");
        }
        break;
    case AST_VAR:
        // TODO 考虑变量类型
        printf("mov -%d(%%rbp), %%rax\n\t", ast->vpos * 8);
        break;
    case AST_FUNCALL:
        // 调用前 先将参数寄存器压栈，保存执行环境
        for (int i = 0; i < ast->nargs; i++)
        {
            printf("push %%%s\n\t", REGS[i]);
        }
        for (int i = 0; i < ast->nargs; i++)
        {
            // 解析参数
            emit_expr(ast->args[i]);
            printf("mov %%rax, %%%s\n\t", REGS[i]);
        }
        printf("mov $0, %%rax\n\t"); // 将rax初始化为0
        printf("call %s\n\t", ast->fname);
        // 调用后，恢复执行环境
        for (int i = ast->nargs - 1; i >= 0; i--)
        {
            printf("pop %%%s\n\t", REGS[i]);
        }
        break;
    case AST_DECL:
        emit_assign(ast->decl_var, ast->decl_init);
        break;
    case AST_ADDR:
        /* 保证操作数是变量类型 */
        assert(ast->operand->type == AST_VAR);
        /* 将变量在栈中存放地址放入rax */
        printf("lea -%d(%%rbp), %%rax\n\t", ast->operand->vpos * 8);
        break;
    case AST_DEREF:
        /* 保证操作数是指针 */
        assert(ast->operand->ctype->type == CTYPE_PTR);
        emit_expr(ast->operand);
        /* 访存，将值赋予rax */
        printf("mov (%%rax), %%rax\n\t");
        break;
    default:
        // 其他情况， 解析二元运算树
        emit_binop(ast);
    }
}

static char *ctype_to_string(Ctype *ctype)
{
    String *s;
    switch (ctype->type)
    {
    case CTYPE_VOID:
        return "void";
    case CTYPE_INT:
        return "int";
    case CTYPE_CHAR:
        return "char";
    case CTYPE_STR:
        return "string";
    case CTYPE_PTR:
        s = make_string();
        string_appendf(s, "%s", ctype_to_string(ctype->ptr));
        string_append(s, '*');
        return get_cstring(s);
    default:
        error("Unknown ctype: %d", ctype);
    }
}

static void ast_to_string_int(Ast *ast, String *buf)
{
    char *left, *right;
    switch (ast->type)
    {
    case AST_LITERAL:
        switch (ast->ctype->type)
        {
        case CTYPE_INT:
            string_appendf(buf, "%d", ast->ival);
            break;
        case CTYPE_CHAR:
            string_appendf(buf, "'%c'", ast->c);
            break;
        case CTYPE_STR:
            string_appendf(buf, "\"%s\"", quote(ast->sval));
            break;
        default:
            error("internal error");
        }
        break;
    case AST_VAR:
        string_appendf(buf, "%s", ast->vname);
        break;
    case AST_FUNCALL:
        string_appendf(buf, "%s(", ast->fname);
        for (int i = 0; i < ast->nargs; i++)
        {
            string_appendf(buf, "%s", ast_to_string(ast->args[i]));
            if (i < ast->nargs - 1)
                string_appendf(buf, ",");
        }
        string_appendf(buf, ")");
        break;
    case AST_DECL:
        string_appendf(buf, "(decl %s %s %s)",
                       ctype_to_string(ast->decl_var->ctype),
                       ast->decl_var->vname,
                       ast_to_string(ast->decl_init));
        break;
    case AST_ADDR:
        string_appendf(buf, "(& %s)", ast_to_string(ast->operand));
        break;
    case AST_DEREF:
        string_appendf(buf, "(* %s)", ast_to_string(ast->operand));
        break;
    default:
        left = ast_to_string(ast->left);
        right = ast_to_string(ast->right);
        string_appendf(buf, "(%c %s %s)", ast->type, left, right);
    }
}

static char *ast_to_string(Ast *ast)
{
    String *s = make_string();
    ast_to_string_int(ast, s);
    return get_cstring(s);
}

int main(int argc, char **argv)
{
    int want_ast_tree = (argc > 1 && !strcmp("-p", argv[1]));
    Ast *exprs[EXPR_LEN];
    int i;
    for (i = 0; i < EXPR_LEN; i++)
    {
        Ast *ast = parse_decl_or_stmt();
        if (!ast)
            break;
        exprs[i] = ast;
    }
    int nexpr = i;
    if (!want_ast_tree)
    {
        emit_data_section();
        printf("\t.text\n\t"
               ".global mymain\n"
               "mymain:\n\t"
               // 堆栈平衡
               "push %%rbp\n\t"
               "mov %%rsp, %%rbp\n\t");
        if (vars)
            printf("sub $%d, %%rsp\n\t", vars->vpos * 8);
    }
    for (i = 0; i < nexpr; i++)
    {
        if (want_ast_tree)
            printf("%s", ast_to_string(exprs[i]));
        else
            emit_expr(exprs[i]);
    }
    if (!want_ast_tree)
    {
        // 堆栈平衡
        // printf("add $200, %%rsp\n\t"
        //        "pop %%rbp\n\t"
        //        "ret");
        printf("leave\n\t"
               "ret");
    }
    printf("\n");
    return 0;
}
