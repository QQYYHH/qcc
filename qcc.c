/*
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:48:11
 * @LastEditTime: 2022-04-10 21:42:16
 * @LastEditors: QQYYHH
 * @Description: 主函数
 * @FilePath: /pwn/compiler/qcc.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>

#define BUFLEN 256

// 增加 AST节点类型的枚举定义
enum
{
    AST_OP_PLUS,
    AST_OP_MINUS,
    AST_INT,
    AST_STR,
};

// 增加AST节点定义
typedef struct Ast
{
    int type;
    // 匿名联合，对应不同AST类型
    union
    {
        int ival;
        char *sval;
        struct
        {
            struct Ast *left;
            struct Ast *right;
        };
    };
} Ast;

void error(char *fmt, ...) __attribute__((noreturen));
void emit_intexpr(Ast *ast);
// 递归下降语法分析函数的定义
Ast *parse_string(void);
Ast *parse_expr(void);

void error(char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(1);
}

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
    return r;
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
    else if (c == EOF)
    {
        error("unexpected EOF!");
    }
    else
    {
        error("Don't know how to handle '%c'", c);
    }
}

Ast *parse_expr2(Ast *left)
{
    skip_space();
    int c = getc(stdin);
    if (c == EOF)
        return left;
    int op;
    if (c == '+')
        op = AST_OP_PLUS;
    else if (c == '-')
        op = AST_OP_MINUS;
    else
        error("Operator expected, but got '%c'", c);
    skip_space();
    Ast *right = parse_prim();
    left = make_ast_op(op, left, right);
    return parse_expr2(left);
}

Ast *parse_expr(void)
{
    Ast *left = parse_prim();
    return parse_expr2(left);
}

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
                error("Unterminated string");
        }
        buf[i++] = c;
        if (i == BUFLEN - 1)
            error("String too long");
    }
    buf[i] = '\0';
    return make_ast_str(buf);
}

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

void emit_string(Ast *ast)
{
    printf("\t.data\n"
           ".mydata:\n\t"
           ".string \"");
    print_quote(ast->sval);
    printf("\"\n\t"
           ".text\n\t"
           ".global stringfn\n"
           "stringfn:\n\t"
           "lea .mydata(%%rip) %%rax\n\t"
           "ret\n");
    return;
}

void emit_binop(Ast *ast)
{
    char *op;
    if (ast->type == AST_OP_PLUS)
        op = "add";
    else if (ast->type == AST_OP_MINUS)
        op = "sub";
    else
        error("invalid operator");
    emit_intexpr(ast->left);
    printf("push %%rax\n\t");
    emit_intexpr(ast->right);
    printf("mov %%rax, %%rbx\n\t");
    printf("pop %%rax\n\t");
    printf("%s %%rbx, %%rax\n\t", op);
}

void ensure_intexpr(Ast *ast)
{
    if (ast->type != AST_OP_PLUS &&
        ast->type != AST_OP_MINUS &&
        ast->type != AST_INT)
        error("integer or binary operator expected");
}

void emit_intexpr(Ast *ast)
{
    ensure_intexpr(ast);
    if (ast->type == AST_INT)
        printf("mov $%d, %%rax\n\t", ast->ival);
    else
        emit_binop(ast);
}

void print_ast(Ast *ast)
{
    switch (ast->type)
    {
    case AST_OP_PLUS:
        printf("(+ ");
        goto print_op;
    case AST_OP_MINUS:
        printf("(- ");
    print_op:
        print_ast(ast->left);
        printf(" ");
        print_ast(ast->right);
        printf(")");
    case AST_INT:
        printf("%d", ast->ival);
        break;
    case AST_STR:
        print_quote(ast->sval);
        break;
    default:
        error("should not reach here");
    }
}

void compile(Ast *ast)
{
    if (ast->type == AST_STR)
        emit_string(ast);
    else
    {
        printf("\t.text\n\t"
               ".global intfn\n"
               "intfn:\n\t");
        emit_binop(ast);
        printf("ret\n");
    }
}

int main(int argc, char **argv)
{
    Ast *ast = parse_expr();
    compile(ast);
    return 0;
}
