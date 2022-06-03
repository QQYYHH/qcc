/*
 * @Author: QQYYHH
 * @Date: 2022-04-22 14:14:29
 * @LastEditTime: 2022-06-03 16:06:23
 * @LastEditors: QQYYHH
 * @Description:
 * @FilePath: /pwn/qcc/qcc.h
 * welcome to my github: https://github.com/QQYYHH
 */
#ifndef QCC_H
#define QCC_H

#include <stdbool.h>
#include "list.h"

// ============================ Token ================================
enum
{
    TTYPE_IDENT,
    // + - * / ( ) , {} ; 等其它一些特殊符号
    TTYPE_PUNCT,
    TTYPE_INT,
    TTYPE_CHAR,
    TTYPE_STRING,
};

typedef struct
{
    int type;
    union
    {
        int ival;
        char *sval;
        // + - * / ( ) , {} ; 等其它一些特殊符号
        char punct;
        char c;
    };
} Token;

typedef struct
{
    char *body;
    int nalloc; // 总长度
    int len; // 当前长度
} String;

// ============================ AST ================================
// 增加 AST节点类型的枚举定义
enum
{
    AST_LITERAL, // 字面量，包括常量、字符
    AST_STRING,
    AST_LVAR, // 局部变量
    AST_GVAR, // 全局变量
    AST_FUNCALL,
    AST_DECL,       // declaration
    AST_ARRAY_INIT, // 数组初始化
    AST_ADDR,       // 代表 & 单目运算
    AST_DEREF,      // 代表 * 单目运算
    AST_IF, 
    AST_COMPOUND_STMT, // compound stmts
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
    // 数组中元素的个数
    int size;
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
            char *slabel;
        };
        // Local Variable
        struct
        {
            char *lname;
            // 局部变量相对rbp的偏移
            int loff;
        };
        // Global Variable
        struct
        {
            char *gname;
            // 全局变量在数据段或者bss段的标签
            char *glabel;
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
            struct List *args;
        };
        // Declaration
        struct
        {
            struct Ast *decl_var;
            struct Ast *decl_init;
        };
        // Array Initializer
        struct
        {
            // 大括号{}中 对数组进行初始化的 ast指针数组
            struct List *array_init;
        };
        // if statement
        struct
        {
            struct Ast *cond;
            struct Ast *then;
            struct Ast *els;
        };
        /* compound statements(statements in one function or block) */ 
        struct List *stmts;
    };
} Ast;

#define error(...) \
    errorf(__FILE__, __LINE__, __VA_ARGS__)

#define warn(...) \
    fprintf(stderr, "warning: " __VA_ARGS__)

#define assert(expr)                           \
    do                                         \
    {                                          \
        if (!(expr))                           \
            error("Assertion failed: " #expr); \
    } while (0)
    
#define swap(a, b)         \
    {                      \
        typeof(a) tmp = a; \
        a = b;             \
        b = tmp;           \
    }


extern void errorf(char *file, int line, char *fmt, ...) __attribute__((noreturn));
// extern void warn(char *fmt, ...) __attribute__((noreturn));

extern String *make_string(void);
extern char *get_cstring(String *s);
extern void string_append(String *s, char c);
extern void string_appendf(String *s, char *fmt, ...);

extern char *token_to_string(Token *tok);
extern bool is_punct(Token *tok, char c);
extern bool is_ident(Token *tok, char *s);
extern void unget_token(Token *tok);
extern Token *peek_token(void);
extern Token *read_token(void);

extern char *quote(char *);
extern char *make_next_label(void);

extern void emit_expr(Ast *ast);
extern char *ast_to_string(Ast *ast);
extern char *ctype_to_string(Ctype *ctype);
extern void print_asm_header(void);

extern Ast *parse_decl_or_stmt(void);

extern List *globals;
extern List *locals;
extern Ctype *ctype_int;
extern Ctype *ctype_char;

#endif /* QCC_H */