/*
 * @Author: QQYYHH
 * @Date: 2022-05-08 19:35:20
 * @LastEditTime: 2022-05-09 16:01:28
 * @LastEditors: QQYYHH
 * @Description: parser
 * @FilePath: /pwn/qcc/parser.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "qcc.h"

#define MAX_ARGS 6

// 全局、局部变量表
Ast *globals = NULL;
Ast *locals = NULL;

// int, char 类型
Ctype *ctype_int = &(Ctype){CTYPE_INT, NULL};
Ctype *ctype_char = &(Ctype){CTYPE_CHAR, NULL};

// 控制全局变量的标签序号
static int labelseq = 0;

static Ast *parse_expr(int prev_priority);
static Ctype *make_ptr_type(Ctype *ctype);
static Ctype *make_array_type(Ctype *ctype, int size);

// ============================ make AST ================================

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
// 产生全局变量在.data or .bss 的标签
char *make_next_label(void)
{
    String *s = make_string();
    string_appendf(s, ".L%d", labelseq++);
    return get_cstring(s);
}

// 字符串本质上是全局字符数组
static Ast *make_ast_str(char *str)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_STRING;
    r->ctype = make_array_type(ctype_char, strlen(str) + 1);
    r->sval = str;
    r->slabel = make_next_label();
    r->next = globals;
    globals = r;
    return r;
}

static Ast *make_ast_lvar(Ctype *ctype, char *name)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_LVAR;
    r->ctype = ctype;
    r->lname = name;
    r->next = NULL;
    // 附加到链表尾部
    if (locals)
    {
        Ast *p;
        for (p = locals; p->next; p = p->next)
            ;
        p->next = r;
    }
    else
    {
        locals = r;
    }
    return r;
}

/**
 * ctype 是指针类型，指向数组元素，创建局部数组对应的reference
 * 指针地址作为基址，off代表以指针所指向变量类型为单位的偏移量
 * 符合上述场景的都可以用 引用抽象语法树来表示
 * @lvar 被引用的局部数组元素
 * @off 数组元素在数组中的偏移量
 */
static Ast *make_ast_lref(Ctype *ctype, Ast *lvar, int off)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_LREF;
    r->ctype = ctype;
    r->lref = lvar;
    r->lrefoff = off;
    return r;
}

static Ast *make_ast_gvar(Ctype *ctype, char *name, bool filelocal)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_GVAR;
    r->ctype = ctype;
    r->gname = name;
    r->glabel = filelocal ? make_next_label() : name;
    r->next = NULL;
    if (globals)
    {
        Ast *p;
        for (p = locals; p->next; p = p->next)
            ;
        p->next = r;
    }
    else
    {
        globals = r;
    }
    return r;
}

/**
 * 创建全局数组对应的引用变量
 * @gvar 被引用的全局数组元素
 * @off 当前引用元素在数组中的偏移量
 */
static Ast *make_ast_gref(Ctype *ctype, Ast *gvar, int off)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_GREF;
    r->ctype = ctype;
    r->gref = gvar;
    r->grefoff = off;
    return r;
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

static Ast *make_ast_decl(Ast *var, Ast *init)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_DECL;
    r->ctype = NULL;
    r->decl_var = var;
    r->decl_init = init;
    return r;
}

/**
 * @array_init 大括号{}中数组元素的初始化值
 */
static Ast *make_ast_array_init(int size, Ast **array_init)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_ARRAY_INIT;
    r->ctype = NULL;
    r->size = size;
    r->array_init = array_init;
    return r;
}

// 创建数组类型
static Ctype *make_array_type(Ctype *ptr_ctype, int size)
{
    Ctype *r = malloc(sizeof(Ctype));
    r->type = CTYPE_ARRAY;
    r->ptr = ptr_ctype;
    r->size = size;
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

static Ast *find_var(char *name)
{
    // 先遍历局部链表
    for (Ast *v = locals; v; v = v->next)
    {
        if (!strcmp(name, v->lname))
            return v;
    }
    // 再遍历全局链表
    for (Ast *v = globals; v; v = v->next)
    {
        if (!strcmp(name, v->gname))
            return v;
    }
    return NULL;
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

// ============================ parse ================================
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
 * prim := number | char | string | variable | NULL
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
        switch (b->type)
        {
        case CTYPE_INT:
        case CTYPE_CHAR:
            return ctype_int;
        case CTYPE_ARRAY:
        case CTYPE_PTR:
            return b;
        }
        error("internal error");
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

static Ctype *result_type(char op, Ctype *a, Ctype *b)
{
    jmp_buf jmpbuf;
    if (setjmp(jmpbuf) == 0)
        return result_type_int(&jmpbuf, op, a, b);
    error("incompatible operands: %c: <%s> and <%s>",
          op, ctype_to_string(a), ctype_to_string(b));
}

// 确保左子节点ast是 变量或引用类型
static void ensure_lvalue(Ast *ast)
{
    switch (ast->type)
    {
    case AST_LVAR:
    case AST_LREF:
    case AST_GVAR:
    case AST_GREF:
        return;
    default:
        error("lvalue expected, but got %s", ast_to_string(ast));
    }
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

// 仅将数组类型转换为引用【指针】类型，方便后续操作，其它类型的ast则直接返回
static Ast *convert_array(Ast *ast)
{
    // 字符数组
    if (ast->type == AST_STRING)
        return make_ast_gref(make_ptr_type(ctype_char), ast, 0);
    if (ast->ctype->type != CTYPE_ARRAY)
        return ast;
    if (ast->type == AST_LVAR)
        return make_ast_lref(make_ptr_type(ast->ctype->ptr), ast, 0);
    if (ast->type != AST_GVAR)
        error("Internal error: Gvar expected, but got %s", ast_to_string(ast));
    return make_ast_gref(make_ptr_type(ast->ctype->ptr), ast, 0);
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
        int prio = priority(tok->punct);
        /* 赋值语句中 = 的优先级比较特殊，相同符号前面的优先级 < 后面；对于+ - * / 来说，相同符号前面的优先级 > 后面 */
        /* 因此 优先级相等的这种情况要单独拿出来讨论 */
        int is_equal = is_punct(tok, '=');
        if (prio < prev_priority || ((prio == prev_priority) && !is_equal))
        {
            unget_token(tok);
            return ast;
        }
        // 如果是赋值语句，确保左子节点的类型是 变量或者数组引用
        // 暂不支持直接对 某个地址复制
        if (is_equal)
            ensure_lvalue(ast);
        // 这里和源码有所区别
        // 仅将数组类型变量 转换为引用【指针】类型，方便后续生成代码
        ast = convert_array(ast);
        Ast *right = parse_expr(prio);
        right = convert_array(right);
        Ctype *ctype = result_type(tok->punct, ast->ctype, right->ctype);

        // 这里有一个交换操作，将指针类型的子树放在左边，方便后续处理
        // 这种交换操作并不影响运算的优先级
        // 但会影响 减法 操作，TODO fix
        if (!is_punct(tok, '=') && ctype->type == CTYPE_PTR && ast->ctype->type != CTYPE_PTR)
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
 * 数组的初始化数据部分
 * decl_array_init := "char* array" | { expr, expr, ... }
 * @ctype array_ctype
 */
static Ast *parse_decl_array_initializer(Ctype *ctype)
{
    Token *tok = read_token();
    // 字符数组
    if (ctype->ptr->type == CTYPE_CHAR && tok->type == TTYPE_STRING)
        return make_ast_str(tok->sval);
    // 其它数组
    if (!is_punct(tok, '{'))
        error("Expected an initializer list, but got %s", token_to_string(tok));
    Ast **init = malloc(sizeof(Ast *) * ctype->size);
    for (int i = 0; i < ctype->size; i++)
    {
        init[i] = parse_expr(0);
        // 保证初始化元素类型 和 数组类型兼容
        result_type('=', init[i]->ctype, ctype->ptr);
        tok = read_token();
        if (is_punct(tok, '}') && (i == ctype->size - 1))
            break;
        if (!is_punct(tok, ','))
            error("comma expected, but got %s", token_to_string(tok));
        if (i == ctype->size - 1)
        {
            tok = read_token();
            if (!is_punct(tok, '}'))
                error("'}' expected, but got %s", token_to_string(tok));
            break;
        }
    }
    return make_ast_array_init(ctype->size, init);
}

/**
 * decl_init := array_init | expr
 */
static Ast *parse_declinitializer(Ctype *ctype)
{
    if (ctype->type == CTYPE_ARRAY)
        return parse_decl_array_initializer(ctype);
    return parse_expr(0);
}

/**
 * 声明
 * decl := ctype identifer = decl_init
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
    Token *tok_varname = tok;
    for (;;)
    {
        tok = read_token();
        if (is_punct(tok, '['))
        {
            // TODO 数组size 支持复杂表达式
            // 目前仅支持 整数字面量
            Ast *size = parse_expr(0);
            if (size->type != AST_LITERAL || size->ctype->type != CTYPE_INT)
                error("Integer expected, but got %s", ast_to_string(size));
            expect(']');
            ctype = make_array_type(ctype, size->ival);
        }
        else
        {
            unget_token(tok);
            break;
        }
    }
    Ast *var = make_ast_lvar(ctype, tok_varname->sval);
    expect('=');
    Ast *init = parse_declinitializer(ctype);
    return make_ast_decl(var, init);
}

/**
 * decl or stmt
 * 目前来讲，stmt就是表达式
 */
Ast *parse_decl_or_stmt()
{
    // 仅作比较，不将token从缓冲区删除
    Token *tok = peek_token();
    if (!tok)
        return NULL;
    Ast *ast = is_type_keyword(tok) ? parse_decl() : parse_expr(0);
    expect(';');
    return ast;
}

char *ctype_to_string(Ctype *ctype)
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
        string_appendf(s, "[%d]", ctype->size);
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
        default:
            error("internal error");
        }
        break;
    case AST_STRING:
        string_appendf(buf, "\"%s\"", quote(ast->sval));
        break;
    case AST_LVAR:
        string_appendf(buf, "%s", ast->lname);
        break;
    case AST_GVAR:
        string_appendf(buf, "%s", ast->gname);
        break;
    case AST_LREF:
        string_appendf(buf, "%s[%d]", ast_to_string(ast->lref), ast->lrefoff);
        break;
    case AST_GREF:
        string_appendf(buf, "%s[%d]", ast_to_string(ast->gref), ast->grefoff);
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
                       ast->decl_var->lname,
                       ast_to_string(ast->decl_init));
        break;
    case AST_ADDR:
        string_appendf(buf, "(& %s)", ast_to_string(ast->operand));
        break;
    case AST_DEREF:
        string_appendf(buf, "(* %s)", ast_to_string(ast->operand));
        break;
    case AST_ARRAY_INIT:
        string_appendf(buf, "{");
        for (int i = 0; i < ast->size; i++)
        {
            ast_to_string_int(ast->array_init[i], buf);
            if (i != ast->size - 1)
                string_appendf(buf, ",");
        }
        string_appendf(buf, "}");
        break;
    default:
        left = ast_to_string(ast->left);
        right = ast_to_string(ast->right);
        string_appendf(buf, "(%c %s %s)", ast->type, left, right);
    }
}

char *ast_to_string(Ast *ast)
{
    String *s = make_string();
    ast_to_string_int(ast, s);
    return get_cstring(s);
}