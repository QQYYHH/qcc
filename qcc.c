/*
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:48:11
 * @LastEditTime: 2022-04-22 13:01:42
 * @LastEditors: QQYYHH
 * @Description: 主函数
 * @FilePath: /pwn/qcc/qcc.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>

#define BUFLEN 256
#define MAX_ARGS 6
// 最大表达式的数量
#define EXPR_LEN 100

// 增加 AST节点类型的枚举定义
enum
{
    AST_INT,
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
        int ival;
        // string
        struct
        {
            char *sval;
            // 字符串在程序中保存的位置
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
        // 函数
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

void error(char *fmt, ...) __attribute__((noreturen));
void emit_expr(Ast *ast);
void emit_binop(Ast *ast);
// 递归下降语法分析函数的定义
Ast *parse_string(void);
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

void skip_space(void)
{
    int c;
    while ((c = getc(stdin)) != EOF)
    {
        if (isspace(c))
            continue;
        // 如果不是空白字符，把字符重新放回到输入流
        ungetc(c, stdin);
        break;
    }
}

// ===================== parse ====================
/**
 * 常数
 * number := digit
 */
Ast *parse_number(int n)
{
    for (;;)
    {
        int c = getc(stdin);
        if (!isdigit(c))
        {
            ungetc(c, stdin);
            return make_ast_int(n);
        }
        n = n * 10 + (c - '0');
    }
}
/**
 * 字符串常量
 * string := "xxx"
 */ 
Ast *parse_string(void)
{
    char *buf = malloc(BUFLEN);
    int i = 0;
    for (;;)
    {
        int c = getc(stdin);
        if (c == EOF)
            error("Unterminated string");
        if (c == '"')
            break;
        // 转义字符
        if (c == '\\')
        {
            c = getc(stdin);
            if (c == EOF)
                error("Unterminated \\");
        }
        buf[i++] = c;
        if (i == BUFLEN - 1)
            error("String too long");
    }
    buf[i] = '\0';
    return make_ast_str(buf);
}

/**
 * 标识符
 * identifier := alnum
 */
char *parse_ident(char c)
{
    char *buf = malloc(BUFLEN);
    buf[0] = c;
    int i = 1;
    for (;;)
    {
        c = getc(stdin);
        // alnum: alpha + number
        if (!isalnum(c))
        {
            ungetc(c, stdin);
            break;
        }
        buf[i++] = c;
        if (i == BUFLEN - 1)
            error("Identifier too long");
    }
    buf[i] = '\0';
    return buf;
}

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
        skip_space();
        int c = getc(stdin);
        if (c == ')')
            break;
        ungetc(c, stdin);
        args[i] = parse_expr2(0);
        nargs++;
        c = getc(stdin);
        if (c == ')')
            break;
        if (c == ',')
        {
            skip_space();
            int c2 = getc(stdin);
            if (c2 == ')')
                error("Can not find next arg");
            ungetc(c2, stdin);
        }
        else
            error("Unexpected character: '%c'", c);
    }
    return make_ast_funcall(fname, nargs, args);
}

/**
 * 常量或者函数
 * ident_or_func := identifier | function
 * function := identifer ( func_args )
 */
Ast *parse_ident_or_func(char c)
{
    char *name = parse_ident(c);
    skip_space();
    int c2 = getc(stdin);
    // funcall
    if (c2 == '(')
        return parse_func_args(name);
    // identifier
    ungetc(c2, stdin);
    Ast *v = find_var(name);
    return v? v: make_ast_var(name);
}

/**
 * 基本单元，可以是常量、字符串常量、标识符 或者为空
 * prim := number | string | symbols [variable] | NULL
 */
Ast *parse_prim(void)
{
    int c = getc(stdin);
    if (isdigit(c))
    {
        return parse_number(c - '0');
    }
    else if (c == '"')
    {
        return parse_string();
    }
    else if (isalnum(c))
        return parse_ident_or_func(c);
    else if (c == EOF)
    {
        return NULL;
    }
    error("Don't know how to handle '%c'", c);
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
    skip_space();
    Ast *ast = parse_prim();
    if (!ast)
        return NULL;
    for (;;)
    {
        skip_space();
        int c = getc(stdin);
        if (c == EOF)
            return ast;
        int prio = priority(c);
        if (prio <= prev_priority)
        {
            ungetc(c, stdin);
            return ast;
        }
        ast = make_ast_op(c, ast, parse_expr2(prio));
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
    skip_space();
    int c = getc(stdin);
    if (c != ';')
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
               "ret\n");
    }

    return 0;
}
