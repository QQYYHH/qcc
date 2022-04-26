/*
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:48:11
 * @LastEditTime: 2022-04-26 16:03:28
 * @LastEditors: QQYYHH
 * @Description: 主函数
 * @FilePath: /pwn/qcc/main.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qcc.h"

#define MAX_ARGS 6
// 最大表达式的数量
#define EXPR_LEN 100

#define swap(a, b) \
    {              \
        typeof(a) tmp = a; a = b; b = tmp; \
    }

// 增加 AST节点类型的枚举定义
enum
{
    AST_INT,
    AST_CHAR, 
    AST_STR,
    AST_VAR,
    AST_FUNCALL,
    AST_DECL, // declaration
};

// 不同的C类型
enum {
  CTYPE_VOID,
  CTYPE_INT,
  CTYPE_CHAR,
  CTYPE_STR,
};

// 增加AST节点定义
typedef struct Ast
{
    int type;
    // 子树代表的C类型，void, int, char, str
    int ctype;
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
        struct{
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
        // Function call
        struct
        {
            char *fname;
            int nargs;
            struct Ast **args;
        };
        // Declaration
        struct{
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

static void emit_expr(Ast *ast);
// 必要的递归下降语法分析函数的定义
static Ast *parse_expr(int prev_priority);
static char *ast_to_string(Ast *ast);


// ===================== make AST ====================

/**
 * 二元操作树，表达式抽象语法树
 */
static Ast *make_ast_op(int type, int ctype, Ast *left, Ast *right)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = type;
    r->ctype = ctype;
    r->left = left;
    r->right = right;
    return r;
}

static Ast *make_ast_char(char c){
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_CHAR;
    r->ctype = CTYPE_CHAR;
    r->c = c;
    return r;
}

static Ast *make_ast_int(int val)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_INT;
    r->ctype = CTYPE_INT;
    r->ival = val;
    return r;
}

static Ast *make_ast_str(char *str)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_STR;
    r->ctype = CTYPE_STR;
    r->sval = str;
    r->snext = strings;
    r->sid = strings? strings->sid + 1: 0;
    strings = r;
    return r;
}

static Ast *make_ast_var(int ctype, char *vname)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_VAR;
    r->ctype = ctype;
    r->vname = vname;
    r->vpos = vars? vars->vpos + 1: 1;
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
    r->ctype = CTYPE_INT;
    r->fname = fname;
    r->nargs = nargs;
    r->args = args;
    return r;
}

static bool is_right_assoc(char op){
    return op == '=';
}

static Ast *make_ast_decl(Ast *var, Ast *init){
  Ast *r = malloc(sizeof(Ast));
  r->type = AST_DECL;
  r->decl_var = var;
  r->decl_init = init;
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
static char result_type(char op, Ast *a, Ast *b)
{
    int swapped = false;
    if (a->ctype > b->ctype)
    {
        swap(a, b);
        swapped = true;
    }
    switch (a->ctype)
    {
    /* void不能和任何类型发生运算 */
    case CTYPE_VOID:
        goto err;
    /* int op [int, char] -> int */
    /* int op str -> error */
    case CTYPE_INT:
        switch (b->ctype)
        {
        case CTYPE_INT:
        case CTYPE_CHAR:
            return CTYPE_INT;
        case CTYPE_STR:
            goto err;
        }
        error("internal error");
    /* char op char -> int */
    /* char op str -> error */
    case CTYPE_CHAR:
        switch (b->ctype)
        {
        case CTYPE_CHAR:
            return CTYPE_INT;
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
    if (swapped)
        swap(a, b);
    error("incompatible operands: %s and %s for %c",
          ast_to_string(a), ast_to_string(b), op);
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
        if(is_punct(tok, ')')) break;
        unget_token(tok);
        args[i] = parse_expr(0);
        nargs++;
        tok = read_token();
        if(is_punct(tok, ')')) break;
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
    if(!v)
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
  if (!tok) return NULL;
  switch (tok->type) {
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

// 确保左子节点ast是 变量类型
static void ensure_lvalue(Ast *ast){
    if (ast->type != AST_VAR)
        error("variable expected");
}

/**
 * 混合运算表达式 或 赋值语句
 * prev_priority 代表上一个符号的优先级
 * expr2 := + - * / = 混合运算以及赋值语句
 *
 * expr2 := prim cal expr2 | prim
 * cal := + - * / =
 */
static Ast *parse_expr(int prev_priority)
{
    Ast *ast = parse_prim();
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
        if(is_equal)
            ensure_lvalue(ast);
        Ast *right = parse_expr(prio);
        char ctype = result_type(tok->punct, ast, right);
        ast = make_ast_op(tok->punct, ctype, ast, right);
    }
}

static int get_ctype(Token *tok) {
  if (tok->type != TTYPE_IDENT)
    return -1;
  if (!strcmp(tok->sval, "int"))
    return CTYPE_INT;
  if (!strcmp(tok->sval, "char"))
    return CTYPE_CHAR;
  if (!strcmp(tok->sval, "string"))
    return CTYPE_STR;
  return -1;
}

static bool is_type_keyword(Token *tok) {
  return get_ctype(tok) != -1;
}
static void expect(char punct) {
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
static Ast *parse_decl(){
    Token *tok = read_token();
    int ctype = get_ctype(tok);
    Token *tok_name = read_token();
    if(!tok_name)
        error("Unexpected terminated..");
    if(tok_name->type != TTYPE_IDENT)
        error("Identifier expected, but got %s", token_to_string(tok_name));
    Ast *var = make_ast_var(ctype, tok_name->sval);
    expect('=');
    Ast *init = parse_expr(0);
    return make_ast_decl(var, init);
}

/**
 * decl or stmt
 * 目前来讲，stmt就是表达式
 */
static Ast *parse_decl_or_stmt(){
    // 仅作比较，不将token从缓冲区删除
    Token *tok = peek_token();
    if(!tok) return NULL;
    Ast *ast = is_type_keyword(tok)? parse_decl(): parse_expr(0);
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

static void emit_assign(Ast *var, Ast *value){
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
    case AST_INT:
        printf("mov $%d, %%rax\n\t", ast->ival);
        break;
    case AST_VAR:
        // TODO 考虑变量类型
        printf("mov -%d(%%rbp), %%rax\n\t", ast->vpos * 8);
        break;
    case AST_CHAR:
        printf("mov $%d, %%rax\n\t", ast->c);
        break;
    case AST_STR:
        // x64特有的rip相对寻址，.s是数据段中字符串的标识符
        // 比如数据段中有.s0, .s1, .s2等，分别代表不同的字符串
        printf("lea .s%d(%%rip), %%rax\n\t", ast->sid);
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
    default:
        // 其他情况， 解析二元运算树
        emit_binop(ast);
    }
}

static char *ctype_to_string(int ctype) {
  switch (ctype) {
    case CTYPE_VOID: return "void";
    case CTYPE_INT:  return "int";
    case CTYPE_CHAR: return "char";
    case CTYPE_STR:  return "string";
    default: error("Unknown ctype: %d", ctype);
  }
}

static void ast_to_string_int(Ast *ast, String *buf)
{
    char *left, *right;
    switch (ast->type)
    {
    case AST_INT:
        string_appendf(buf, "%d", ast->ival);
        break;
    case AST_CHAR:
        string_appendf(buf, "'%c'", ast->c);
        break;
    case AST_STR:
        string_appendf(buf, "\"%s\"", quote(ast->sval));
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
    default:
        left = ast_to_string(ast->left);
        right = ast_to_string(ast->right);
        string_appendf(buf, "(%c %s %s)", ast->type, left, right);
    }
}

static char *ast_to_string(Ast *ast){
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
               "mov %%rsp, %%rbp\n\t"
               "sub $200, %%rsp\n\t");
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
        printf("add $200, %%rsp\n\t"
               "pop %%rbp\n\t"
               "ret");
    }
    printf("\n");
    return 0;
}
