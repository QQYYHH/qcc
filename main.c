/*
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:48:11
 * @LastEditTime: 2022-05-06 00:55:10
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
    CTYPE_ARRAY, // 数组类型
    CTYPE_PTR,   // 指针类型
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
    // 抽象语法树的C类型
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
// 数组本质是一种指针类型，指向基本单元char类型
// 不论是什么类型的数组，基本单元都可以是char类型，比如一个int元素相当于4个char类型的元素
static Ctype *ctype_array = &(Ctype){CTYPE_ARRAY, &(Ctype){CTYPE_CHAR, NULL}};

static char *ctype_to_string(Ctype *ctype);

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
    r->ctype = ctype_array;
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
static Ctype *result_type_int(jmp_buf *jmpbuf, char op, Ctype *a, Ctype *b)
{
    if (a->type > b->type)
        swap(a, b);
    /**
     * 如果是指针
     */
    if (b->type == CTYPE_PTR)
    {
        /* 指针与其他类型的数据只能做 + - */
        if (op != '+' && op != '-')
            goto err;
        if (a->type != CTYPE_PTR)
        {
            // fprintf(stderr, "warning: Making a pointer from %s\n", ctype_to_string(a));
            warn("Making a pointer from %s\n", ctype_to_string(a));
            return b;
        }
        /* 二者都是指针的情况，递归下去看指向的变量类型 */
        Ctype *r = malloc(sizeof(Ctype));
        r->type = CTYPE_PTR;
        r->ptr = result_type_int(jmpbuf, op, a->ptr, b->ptr);
        return r;
    }

    switch (a->type)
    {
    /* void不能和任何类型发生运算 */
    case CTYPE_VOID:
        goto err;
    case CTYPE_INT:
    case CTYPE_CHAR:
        return ctype_int;
    /* array 本质上是指针类型，因此将其转换为指针类型之后递归判断即可 */
    /* array op array */
    /* array op ptr */
    case CTYPE_ARRAY:
        return result_type_int(jmpbuf, op, make_ptr_type(a->ptr), b);
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
        return result_type_int(&jmpbuf, op, a->ctype, b->ctype);
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
        // 这里有一个交换操作，将指针类型的子树放在左边，方便后续处理
        // 这种交换操作并不影响运算的优先级
        if (ctype->type == CTYPE_PTR && ast->ctype->type != CTYPE_PTR)
            swap(ast, right);
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

static int ctype_shift(Ctype *ctype)
{
    switch (ctype->type)
    {
    case CTYPE_CHAR:
        return 0; // 1 << 0
    case CTYPE_INT:
        return 2; // 1 << 2
    default:
        return 3; // 1 << 3
    }
}
// 某个ctype占用的字节数
static int ctype_size(Ctype *ctype)
{
    return 1 << ctype_shift(ctype);
}

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
    // 考虑变量类型
    switch (ctype_size(var->ctype))
    {
    case 1:
        printf("mov %%al, -%d(%%rbp)\n\t", var->vpos * 8);
        break;
    case 4:
        printf("mov %%eax, -%d(%%rbp)\n\t", var->vpos * 8);
        break;
    case 8:
        printf("mov %%rax, -%d(%%rbp)\n\t", var->vpos * 8);
        break;
    default:
        error("interal error");
    }
    // printf("mov %%rax, -%d(%%rbp)\n\t", var->vpos * 8);
}

/**
 * 指针二元运算树 对应的代码产生方式
 * 因为指针运算需要考虑指针类型，所以特殊一点
 * 比如int *a; a + 2; 相当于一共偏移 2 * 4 = 8个字节，因为一个int类型是4字节
 * 指针只会进行 + - 操作
 */
static void emit_pointer_arithmetic(char op, Ast *left, Ast *right)
{
    /* 确保左子树是指针类型 */
    assert(left->ctype->type == CTYPE_PTR);
    /* 如果左右子树都是指针类型 */
    if(right->ctype->type == CTYPE_PTR){
        /* 确保指针指向的类型一致 */
        /* 且指针之间只有做减法操作才有意义 */
        assert(left->ctype->ptr->type == right->ctype->ptr->type);
        if(op == '+') error("No meaning for ptr plus ptr");
        emit_expr(left);
        printf("push %%rax\n\t");
        emit_expr(right);
        int sft = ctype_shift(left->ctype->ptr);
        printf("mov %%rax, %%rbx\n\t"
           "pop %%rax\n\t"
           "sub %%rbx, %%rax\n\t"
           "sar $%d, %%rax\n\t", sft);
        return ;
    }

    emit_expr(left);
    printf("push %%rax\n\t");
    emit_expr(right);
    /* 根据指针指向的类型，计算偏移量 */
    int sft = ctype_shift(left->ctype->ptr);
    if (sft > 0)
        /* sal 有符号左移动 */
        printf("sal $%d, %%rax\n\t", sft);
    char *s = "add";
    if (op == '-')
        s = "sub";
    printf("mov %%rax, %%rbx\n\t"
           "pop %%rax\n\t"
           "%s %%rbx, %%rax\n\t",
           s);
}

static void emit_binop(Ast *ast)
{
    // 如果是赋值语句
    if (ast->type == '=')
    {
        emit_assign(ast->left, ast->right);
        return;
    }
    // 如果二元运算树是指针类型
    if (ast->ctype->type == CTYPE_PTR)
    {
        emit_pointer_arithmetic(ast->type, ast->left, ast->right);
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
        /* rdx存放余数 */
        /* rax存放商 */
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
        printf("xor %%rax, %%rax\n\t");
        switch (ast->ctype->type)
        {
        case CTYPE_INT:
            printf("mov $%d, %%rax\n\t", ast->ival);
            break;
        case CTYPE_CHAR:
            printf("mov $%d, %%al\n\t", ast->c);
            break;
        /* string */
        case CTYPE_ARRAY:
            // x64特有的rip相对寻址，.s是数据段中字符串的标识符
            // 比如数据段中有.s0, .s1, .s2等，分别代表不同的字符串
            printf("lea .s%d(%%rip), %%rax\n\t", ast->sid);
            break;
        default:
            error("internal error");
        }
        break;
    case AST_VAR:
        printf("xor %%rax, %%rax\n\t");
        // 考虑变量类型
        switch (ctype_size(ast->ctype))
        {
        case 1:
            printf("mov -%d(%%rbp), %%al\n\t", ast->vpos * 8);
            break;
        case 4:
            printf("mov -%d(%%rbp), %%eax\n\t", ast->vpos * 8);
            break;
        case 8:
            printf("mov -%d(%%rbp), %%rax\n\t", ast->vpos * 8);
            break;
        default:
            error("interal error");
        }
        // printf("mov -%d(%%rbp), %%rax\n\t", ast->vpos * 8);
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
        char *reg;
        switch (ctype_size(ast->ctype))
        {
        case 1:
            reg = "bl";
            break;
        case 4:
            reg = "ebx";
            break;
        case 8:
            reg = "rbx";
            break;
        default:
            error("interal error");
        }
        printf("xor %%rbx, %%rbx\n\t");
        printf("mov (%%rax), %%%s\n\t", reg);
        printf("mov %%rbx, %%rax\n\t");
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
    case CTYPE_PTR:
        s = make_string();
        string_appendf(s, "%s", ctype_to_string(ctype->ptr));
        string_append(s, '*');
        return get_cstring(s);
    case CTYPE_ARRAY:
        s = make_string();
        string_appendf(s, "%s", ctype_to_string(ctype->ptr));
        string_appendf(s, "[]");
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
        case CTYPE_ARRAY:
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
