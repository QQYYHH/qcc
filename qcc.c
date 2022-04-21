/*
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:48:11
 * @LastEditTime: 2022-04-21 14:52:03
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

// 增加 AST节点类型的枚举定义
enum
{
    AST_INT,
    AST_STR,
    AST_SYM, 
    AST_FUNCALL, 
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
        // 函数
        struct{
            char *fname;
            int nargs;
            struct Ast **args;
        };
    };
} Ast;

// 全局 变量链表
Var *vars = NULL;
// x64下函数前6个实参会依次放入下列寄存器
char *REGS[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};


void error(char *fmt, ...) __attribute__((noreturen));
void emit_expr(Ast *ast);
void emit_binop(Ast *ast);
void emit_string(Ast *ast);
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
    return r;
}

Ast *make_ast_sym(Var *var){
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_SYM;
    r->var = var;
    return r;
}

Var *find_var(char *name) {
  for (Var *v = vars; v; v = v->next) {
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

Ast *make_ast_funcall(char *fname, int nargs, Ast **args){
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_FUNCALL;
    r->fname = fname;
    r->nargs = nargs;
    r->args = args;
    return r;
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

char *parse_ident(char c){
    char *buf = malloc(BUFLEN);
    buf[0] = c;
    int i = 1;
    for(;;){
        c = getc(stdin);
        // alnum: alpha + number
        if(!isalnum(c)){
            ungetc(c, stdin);
            break;
        }
        buf[i++] = c;
        if(i == BUFLEN - 1)
            error("Identifier too long");
    }
    buf[i] = '\0';
    return buf;
}

Ast *parse_func_args(char *fname){
    Ast **args = malloc(sizeof(Ast *) * (MAX_ARGS + 1));
    int i = 0, nargs = 0;
    for(; i < MAX_ARGS + 1; i++){
        if(i == MAX_ARGS) error("Too many arguments: %s", fname);
        skip_space();
        int c = getc(stdin);
        if(c == ')') break;
        ungetc(c, stdin);
        args[i] = parse_expr2(0);
        nargs++;
        c = getc(stdin);
        if(c == ')') break;
        if(c == ','){
            skip_space();
            int c2 = getc(stdin);
            if(c2 == ')') error("Can not find next arg");
            ungetc(c2, stdin);
        }
        else error("Unexpected character: '%c'", c);
    }
    return make_ast_funcall(fname, nargs, args);
}

Ast *parse_ident_or_func(char c){
    char *name = parse_ident(c);
    skip_space();
    int c2 = getc(stdin);
    // funcall
    if(c2 == '(') return parse_func_args(name);
    // identifier
    ungetc(c2, stdin);
    Var *v = find_var(name);
    if(!v) v = make_var(name);
    return make_ast_sym(v);
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
    else if(isalnum(c)) return parse_ident_or_func(c);
    else if (c == EOF)
    {
        return NULL;
    }
    error("Don't know how to handle '%c'", c);
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
    switch(ast->type){
        case AST_INT:
            printf("mov $%d, %%rax\n\t", ast->ival);    
            break;
        case AST_SYM:
            printf("mov -%d(%%rbp), %%rax\n\t", ast->var->pos * 8);
            break;
        case AST_FUNCALL:
            // 调用前 先将参数寄存器压栈，保存执行环境
            for(int i = 0; i < ast->nargs; i++){
                printf("push %%%s\n\t", REGS[i]);
            }
            for(int i = 0; i < ast->nargs; i++){
                // 解析参数
                emit_expr(ast->args[i]);
                printf("mov %%rax, %%%s\n\t", REGS[i]);
            }
            printf("mov $0, %%rax\n\t"); // 将rax初始化为0
            printf("call %s\n\t", ast->fname);
            // 调用后，恢复执行环境
            for(int i = ast->nargs - 1; i >= 0; i--){
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
        print_quote(ast->sval);
        break;
    case AST_SYM:
        printf("%s", ast->var->name);
        break;
    case AST_FUNCALL:
        printf("%s(", ast->fname);
        for (int i = 0; ast->args[i]; i++) {
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
           "sub $200, %%rsp\n\t");
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
    printf("add $200, %%rsp\n\t"
           "pop %%rbp\n\t"
           "ret\n");
    
    return 0;
}
