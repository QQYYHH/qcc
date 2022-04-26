/*
 * @Author: QQYYHH
 * @Date: 2022-04-22 14:14:29
 * @LastEditTime: 2022-04-26 16:00:46
 * @LastEditors: QQYYHH
 * @Description:
 * @FilePath: /pwn/qcc/qcc.h
 * welcome to my github: https://github.com/QQYYHH
 */
#ifndef QCC_H
#define QCC_H

#include <stdbool.h>

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

#define error(...) \
    errorf(__FILE__, __LINE__, __VA_ARGS__)

extern void errorf(char *file, int line, char *fmt, ...) __attribute__((noreturn));

extern String *make_string(void);
extern char *get_cstring(String *s);
extern void string_append(String *s, char c);
extern void string_appendf(String *s, char *fmt, ...);

extern char *token_to_string(Token *tok);
extern bool is_punct(Token *tok, char c);
extern void unget_token(Token *tok);
extern Token *peek_token(void);
extern Token *read_token(void);

#endif /* QCC_H */