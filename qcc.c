/*
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:48:11
 * @LastEditTime: 2022-04-12 14:13:39
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

// 增加 AST节点类型的枚举定义
enum
{
    AST_OP_PLUS,
    AST_OP_MINUS,
    AST_INT,
    AST_STR,
    AST_SYM, 
};

// 增加对变量的声明
typedef struct Var{
    char *name;
    // 用于控制栈中生成的局部变量的位置
    int pos; 
    struct Var *next;
} Var;

// 增加AST节点定义
typedef struct Ast
{
    int type;
    // 匿名联合，对应不同AST类型
    union
    {
        Var *var;
        int ival;
        char *sval;
        struct
        {
            struct Ast *left;
            struct Ast *right;
        };
    };
} Ast;

// 全局 变量链表
Var *vars = NULL;

void error(char *fmt, ...) __attribute__((noreturen));
void emit_expr(Ast *ast);
void emit_binop(Ast *ast);
void emit_string(Ast *ast);
// 递归下降语法分析函数的定义
Ast *parse_string(void);
Ast *parse_expr(void);
Ast *parse_sym(char c);

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
    return r;
}

Ast *make_ast_sym(Var *var){
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_SYM;
    r->var = var;
    return r;
}

Var *find_var(char *name) {
  Var *v = vars;
  for (; v; v = v->next) {
    if (!strcmp(name, v->name))
      return v;
  }
  return NULL;
}

Var *make_var(char *name){
    Var *v = malloc(sizeof(Var));
    v->name = name;
    v->pos = vars? vars->pos + 1: 1;
    v->next = vars;
    vars = v;
    return v;
}

int priority(char op) {
  switch (op) {
    case '=':
        return 1;
    case '+': case '-':
        return 2;
    case '*': case '/':
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

Ast *parse_sym(char c){
    char *buf = malloc(BUFLEN);
    buf[0] = c;
    int i = 1;
    for(;;){
        c = getc(stdin);
        if(!isalpha(c)){
            ungetc(c, stdin);
            break;
        }
        buf[i++] = c;
        if(i == BUFLEN - 1)
            error("Symbol too long");
    }
    buf[i] = '\0';
    Var *var = find_var(buf);
    if(!var) var = make_var(buf);
    return make_ast_sym(var);
}


/**
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
    else if(isalpha(c)) return parse_sym(c);
    else if (c == EOF)
    {
        return NULL;
    }
    ;error("Don't know how to handle '%c'", c);
}

/**
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
    if(!ast) return NULL;
    for(;;){
        skip_space();
        int c = getc(stdin);
        if(c == EOF) return ast;
        int prio = priority(c);
        if(prio <= prev_priority){
            ungetc(c, stdin);
            return ast;
        }
        ast = make_ast_op(c, ast, parse_expr2(prio));
    }
}
/**
 * expr := expr2 ;
 */
Ast *parse_expr(void)
{
    // 初始化优先级为 0
    Ast *ast = parse_expr2(0);
    if(!ast) return NULL;
    skip_space();
    int c = getc(stdin);
    if(c != ';') error("Unterminated expression");
    return ast;
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

// ===================== emit ====================
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
    // 如果是赋值语句
    if(ast->type == '='){
        emit_expr(ast->right);
        // 如果赋值号左边不是 变量，则抛出异常
        if(ast->left->type != AST_SYM) error("Symbol expected");
        // 假设类型占用 8字节
        printf("mov %%rax, -%d(%%rbp)\n\t", ast->left->var->pos * 8);
        return ;
    }
    // 如果是计算表达式
    char *op;
    switch (ast->type){
        case '+': op = "add"; break;
        case '-': op = "sub"; break;
        case '*': op = "imul"; break;
        case '/': op = "idiv"; break;
        default: error("invalid operator '%c'", ast->type);
    }
    emit_expr(ast->left);
    printf("push %%rax\n\t");
    emit_expr(ast->right);
    printf("mov %%rax, %%rbx\n\t");
    printf("pop %%rax\n\t");
    if(ast->type == '/'){
        printf("mov $0, %%rdx\n\t");
        printf("idiv %%rbx\n\t");
    }
    else{
        printf("%s %%rbx, %%rax\n\t", op);
    }
    
}

void ensure_intexpr(Ast *ast)
{
    switch (ast->type) {
    case '+': case '-': case '*': case '/': case AST_INT:
      return;
    default:
      error("integer or binary operator expected");
  }
}

void emit_expr(Ast *ast)
{

    if (ast->type == AST_INT)
        printf("mov $%d, %%rax\n\t", ast->ival);
    // 如果是变量，把变量的值移入 rax中
    else if(ast->type == AST_SYM)
        printf("mov -%d(%%rbp), %%rax\n\t", ast->var->pos * 8);
    // 如果是 二元运算树
    else
        emit_binop(ast);
}

void print_ast(Ast *ast)
{
    switch (ast->type)
    {
    case AST_INT:
        printf("%d", ast->ival);
        break;
    case AST_STR:
        print_quote(ast->sval);
        break;
    case AST_SYM:
        printf("%s", ast->var->name);
        break;
    default:
        printf("(%c ", ast->type);
        print_ast(ast->left);
        printf(" ");
        print_ast(ast->right);
        printf(")");
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
    printf(".text\n\t"
           ".global mymain\n"
           "mymain:\n\t"
           // 堆栈平衡
           "push %%rbp\n\t"
           "mov %%rsp, %%rbp\n\t"
           "sub $64, %%rsp\n\t");
    for(;;){
        Ast *ast = parse_expr();
        if(!ast) break;
        if(argc > 1 && !strcmp("-p", argv[1])){
            print_ast(ast);
        }
        else{
            emit_expr(ast);
        }
        
    }
    // 堆栈平衡
    printf("add $64, %%rsp\n\t"
           "pop %%rbp\n\t"
           "ret\n");
    
    return 0;
}
