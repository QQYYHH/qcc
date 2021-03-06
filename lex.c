/*
 * @Author: QQYYHH
 * @Date: 2022-04-22 14:30:50
 * @LastEditTime: 2022-06-13 16:47:49
 * @LastEditors: QQYYHH
 * @Description:
 * @FilePath: /pwn/qcc/lex.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "qcc.h"

#define BUFLEN 256

static Token *ungotten = NULL;

static Token *make_ident(String *s)
{
    Token *r = malloc(sizeof(Token));
    r->type = TTYPE_IDENT;
    r->sval = get_cstring(s);
    return r;
}

static Token *make_strtok(String *s)
{
    Token *r = malloc(sizeof(Token));
    r->type = TTYPE_STRING;
    r->sval = get_cstring(s);
    return r;
}

static Token *make_punct(int punct)
{
    Token *r = malloc(sizeof(Token));
    r->type = TTYPE_PUNCT;
    r->punct = punct;
    return r;
}

static Token *make_int(int ival)
{
    Token *r = malloc(sizeof(Token));
    r->type = TTYPE_INT;
    r->ival = ival;
    return r;
}

static Token *make_char(char c)
{
    Token *r = malloc(sizeof(Token));
    r->type = TTYPE_CHAR;
    r->c = c;
    return r;
}

static int getc_nonspace(void)
{
    int c;
    while ((c = getc(stdin)) != EOF)
    {
        if (isspace(c) || c == '\n' || c == '\r')
            continue;
        return c;
    }
    return EOF;
}

/**
 * 常数
 * number := digit
 */
static Token *read_number(char c)
{
    int n = c - '0';
    for (;;)
    {
        c = getc(stdin);
        if (!isdigit(c))
        {
            ungetc(c, stdin);
            return make_int(n);
        }
        n = n * 10 + c - '0';
    }
}

/**
 * 单字符
 */
static Token *read_char(void)
{
    char c = getc(stdin);
    if (c == EOF)
        goto err;
    if (c == '\\')
    {
        c = getc(stdin);
        if (c == EOF)
            goto err;
    }
    char c2 = getc(stdin);
    if (c2 == EOF)
        goto err;
    if (c2 != '\'')
        error("Malformed char literal");
    return make_char(c);
err:
    error("Unterminated char");
}

/**
 * 字符串常量
 * string := "xxx"
 */
static Token *read_string(void)
{
    String *s = make_string();
    for (;;)
    {
        int c = getc(stdin);
        if (c == EOF)
            error("Unterminated string");
        if (c == '"')
            break;
        if (c == '\\')
        {
            c = getc(stdin);
            switch(c){
                case EOF: error("Unterminated \\");
                case '\\': break;
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case '\"': c = '\"'; break; 
                default: error("Unknown quote: %c", c);
            }
        }
        string_append(s, c);
    }
    return make_strtok(s);
}

/**
 * 标识符，首位必须是字母或下划线，后面可以是字母、数字、下划线
 * example: int a = 1; int 和 a 都可以算作标识符
 * identifer := alpha | _ | identifer alnum | identifer _
 */
static Token *read_ident(char c)
{
    String *s = make_string();
    string_append(s, c);
    for (;;)
    {
        int c2 = getc(stdin);
        if (isalnum(c2) || c2 == '_')
        {
            string_append(s, c2);
        }
        else
        {
            ungetc(c2, stdin);
            return make_ident(s);
        }
    }
}

/**
 * @brief 读取连续的两个字符，作为一个token
 * 比如 unary operator ++, --
 * 比较运算符 ==
 * @param c1 当前字符
 * @param expect 期望的下一个字符
 * @param punct_type 这两个字符构成的punctuation类型
 */
static Token *read_repeat(int c1, int expect, int punct_type){
    int c = getc(stdin);
    if(c == expect) return make_punct(punct_type);
    ungetc(c, stdin);
    return make_punct(c1);
}

/**
 * Token 读取调度器
 */
static Token *read_token_dispatcher(void)
{
    int c = getc_nonspace();
    switch (c)
    {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return read_number(c);
    case '"':
        return read_string();
    case '\'':
        return read_char();
    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
    case 'g':
    case 'h':
    case 'i':
    case 'j':
    case 'k':
    case 'l':
    case 'm':
    case 'n':
    case 'o':
    case 'p':
    case 'q':
    case 'r':
    case 's':
    case 't':
    case 'u':
    case 'v':
    case 'w':
    case 'x':
    case 'y':
    case 'z':
    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
    case 'G':
    case 'H':
    case 'I':
    case 'J':
    case 'K':
    case 'L':
    case 'M':
    case 'N':
    case 'O':
    case 'P':
    case 'Q':
    case 'R':
    case 'S':
    case 'T':
    case 'U':
    case 'V':
    case 'W':
    case 'X':
    case 'Y':
    case 'Z':
    case '_':
        return read_ident(c);
    case '/':
    case '*':
    case '(':
    case ')':
    case ',':
    case ';':
    case '&':
    case '[':
    case ']':
    case '{':
    case '}':
    case '!':
    case '>':
    case '<':
        return make_punct(c);
    case '=': return read_repeat('=', '=', PUNCT_EQ);
    case '+': return read_repeat('+', '+', PUNCT_INC);
    case '-': return read_repeat('-', '-', PUNCT_DEC);
    case EOF:
        return NULL;
    default:
        error("Unexpected character: '%c'", c);
    }
}

// 将 Token 转化为所代表的 文本
char *token_to_string(Token *tok)
{
    switch (tok->type)
    {
    case TTYPE_IDENT:
        return tok->sval;
    case TTYPE_PUNCT:
    case TTYPE_CHAR:
    {
        String *s = make_string();
        string_append(s, tok->c);
        return get_cstring(s);
    }
    case TTYPE_INT:
    {
        String *s = make_string();
        string_appendf(s, "%d", tok->ival);
        return get_cstring(s);
    }
    case TTYPE_STRING:
    {
        String *s = make_string();
        string_appendf(s, "\"%s\"", tok->sval);
        return get_cstring(s);
    }
    default:
        error("internal error: unknown token type: %d", tok->type);
    }
}

// token是否代表某个特殊字符 c
bool is_punct(Token *tok, int c)
{
    if (!tok)
        error("Token is null");
    return tok->type == TTYPE_PUNCT && tok->punct == c;
}

bool is_ident(Token *tok, char *s){
    if(!tok) error("Unexpected terminate when determine whether a token is identifier");
    return tok->type == TTYPE_IDENT && !strcmp(tok->sval, s);
}

// 将token 回退到 大小为1 的Token缓冲区
void unget_token(Token *tok)
{
    if (ungotten)
        error("Push back buffer is already full");
    ungotten = tok;
}

/**
 * 从缓冲区中读取下一个token
 */
Token *read_token(void)
{
    // 首先从缓冲区获取
    if (ungotten)
    {
        Token *tok = ungotten;
        ungotten = NULL;
        return tok;
    }
    // 缓冲区无Token，则通过全局调度器读取
    return read_token_dispatcher();
}

// 只是比较当前token，并不从缓冲区中删除
Token *peek_token()
{
    Token *tok = read_token();
    unget_token(tok);
    return tok;
}