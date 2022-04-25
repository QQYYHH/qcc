/*
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:48:11
 * @LastEditTime: 2022-04-25 15:05:12
 * @LastEditors: QQYYHH
 * @Description: 主函数
 * @FilePath: /pwn/qcc/main.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "qcc.h"

#define MAX_ARGS 6
// 最大表达式的数量
#define EXPR_LEN 100

// 增加 AST节点类型的枚举定义
enum
{
    AST_INT,
    AST_CHAR, 
    AST_STR,
    AST_VAR,
    AST_FUNCALL,
};

// 增加AST节点定义
typedef struct Ast
{
    int type;
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
    };
} Ast;

// 全局 变量链表、字符串链表
Ast *vars = NULL;
Ast *strings = NULL;
// x64下函数前6个实参会依次放入下列寄存器
char *REGS[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};

void emit_expr(Ast *ast);
void emit_binop(Ast *ast);
// 必要的递归下降语法分析函数的定义
Ast *parse_expr(void);
Ast *parse_expr2(int prec);

void error(char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(1);
}

// ===================== make AST ====================

Ast *make_ast_op(int type, Ast *left, Ast *right)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = type;
    r->left = left;
    r->right = right;
    return r;
}

Ast *make_ast_char(char c){
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_CHAR;
    r->c = c;
    return r;
}

Ast *make_ast_int(int val)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_INT;
    r->ival = val;
    return r;
}

Ast *make_ast_str(char *str)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_STR;
    r->sval = str;
    r->snext = strings;
    r->sid = strings? strings->sid + 1: 0;
    strings = r;
    return r;
}

Ast *make_ast_var(char *vname)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_VAR;
    r->vname = vname;
    r->vpos = vars? vars->vpos + 1: 1;
    r->vnext = vars;
    vars = r;
    return r;
}

Ast *find_var(char *name)
{
    for (Ast *v = vars; v; v = v->vnext)
    {
        if (!strcmp(name, v->vname))
            return v;
    }
    return NULL;
}

Ast *make_ast_funcall(char *fname, int nargs, Ast **args)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_FUNCALL;
    r->fname = fname;
    r->nargs = nargs;
    r->args = args;
    return r;
}

int priority(char op)
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
 * 函数参数
 * func_args := expr2 | expr2, func_args | NULL
 */
Ast *parse_func_args(char *fname)
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
        args[i] = parse_expr2(0);
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
Ast *parse_ident_or_func(char *name)
{
    Token *tok = read_token();
    // funcall
    if (is_punct(tok, '('))
        return parse_func_args(name);
    // identifier
    unget_token(tok);
    Ast *v = find_var(name);
    return v? v: make_ast_var(name);
}

/**
 * 基本单元，可以是整数常量、单字符、字符串常量、标识符 或者为空
 * prim := number | char | string | variable | funcall | NULL
 */
Ast *parse_prim(void)
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

/**
 * 混合运算表达式 或 赋值语句
 * prev_priority 代表上一个符号的优先级
 * expr2 := + - * / = 混合运算以及赋值语句
 *
 * expr2 := prim cal expr2 | prim
 * cal := + - * / =
 */
Ast *parse_expr2(int prev_priority)
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
        // 后面emit的时候可以检查是否是 运算符
        int prio = priority(tok->punct);
        if (prio <= prev_priority)
        {
            unget_token(tok);
            return ast;
        }
        ast = make_ast_op(tok->punct, ast, parse_expr2(prio));
    }
}
/**
 * 完整表达式，以分号【;】结束
 * expr := expr2 ;
 */
Ast *parse_expr(void)
{
    // 初始化优先级为 0
    Ast *ast = parse_expr2(0);
    if (!ast)
        return NULL;
    Token *tok = read_token();
    if(!is_punct(tok, ';'))
        error("Unterminated expression");
    return ast;
}

// ===================== emit ====================

void print_quote(char *p)
{
    while (*p)
    {
        if (*p == '\"' || *p == '\\')
            printf("\\");
        printf("%c", *p);
        p++;
    }
}

void emit_data_section()
{
    if (!strings)
        return;
    printf("\t.data\n");
    for (Ast *p = strings; p; p = p->snext)
    {
        printf(".s%d:\n\t", p->sid);
        printf(".string \"");
        // printf("%s", p->sval);
        print_quote(p->sval);
        printf("\"\n");
    }
}

void emit_binop(Ast *ast)
{
    // 如果是赋值语句
    if (ast->type == '=')
    {
        emit_expr(ast->right);
        // 如果赋值号左边不是 变量，则抛出异常
        if (ast->left->type != AST_VAR)
            error("Symbol expected");
        // 假设类型占用 8字节
        printf("mov %%rax, -%d(%%rbp)\n\t", ast->left->vpos * 8);
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

void ensure_intexpr(Ast *ast)
{
    switch (ast->type)
    {
    case '+':
    case '-':
    case '*':
    case '/':
    case AST_INT:
        return;
    default:
        error("integer or binary operator expected");
    }
}

void emit_expr(Ast *ast)
{
    switch (ast->type)
    {
    case AST_INT:
        printf("mov $%d, %%rax\n\t", ast->ival);
        break;
    case AST_VAR:
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
    default:
        // 其他情况， 解析二元运算树
        emit_binop(ast);
    }
}

void print_ast(Ast *ast)
{
    switch (ast->type)
    {
    case AST_INT:
        printf("%d", ast->ival);
        break;
    case AST_CHAR:
        printf("%c", ast->c);
        break;
    case AST_STR:
        printf("\"");
        print_quote(ast->sval);
        printf("\"");
        break;
    case AST_VAR:
        printf("%s", ast->vname);
        break;
    case AST_FUNCALL:
        printf("%s(", ast->fname);
        for (int i = 0; ast->args[i]; i++)
        {
            print_ast(ast->args[i]);
            if (ast->args[i + 1])
                printf(",");
        }
        printf(")");
        break;
    default:
        printf("(%c ", ast->type);
        print_ast(ast->left);
        printf(" ");
        print_ast(ast->right);
        printf(")");
    }
}

int main(int argc, char **argv)
{
    int want_ast_tree = (argc > 1 && !strcmp("-p", argv[1]));
    Ast *exprs[EXPR_LEN];
    int i;
    for (i = 0; i < EXPR_LEN; i++)
    {
        Ast *ast = parse_expr();
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
            print_ast(exprs[i]);
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
