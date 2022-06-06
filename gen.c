/*
 * @Author: QQYYHH
 * @Date: 2022-05-08 21:59:28
 * @LastEditTime: 2022-06-06 16:19:38
 * @LastEditors: QQYYHH
 * @Description: x64 code generate
 * @FilePath: /pwn/qcc/gen.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <stdarg.h>
#include "qcc.h"

// x64下函数前6个实参会依次放入下列寄存器
static char *REGS[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};

void emit_expr(Ast *ast);

#define emit(...)        emitf(__LINE__, "\t" __VA_ARGS__)
#define emit_label(...)  emitf(__LINE__, __VA_ARGS__)

extern void emitf(int line, char *fmt, ...);

// ===================== emit ====================

/**
 * @brief 获取数组中元素的类型
 * 需要考虑多维数组的情况
 */
static Ctype *get_array_element_ctype(Ctype *array){
    Ctype *p = array;
    while(p->type == CTYPE_ARRAY) p = p->ptr;
    return p;
}

static int ctype_shift(Ctype *ctype)
{
    switch (ctype->type)
    {
    case CTYPE_CHAR:
        return 0; // 1 << 0
    case CTYPE_INT:
        return 2; // 1 << 2
    default:
        return 3; // 1 << 3
    }
}

// 某个ctype占用的字节数
static int ctype_size(Ctype *ctype)
{
    switch (ctype->type)
    {
    case CTYPE_CHAR:
        return 1;
    case CTYPE_INT:
        return 4;
    case CTYPE_PTR:
        return 8;
    case CTYPE_ARRAY:
        return ctype_size(ctype->ptr) * ctype->size;
    default:
        error("ctype size calculate error");
    }
}

/**
 * 全局数据加载
 * 如果是数组，则仅加载首元素地址
 * .data or .bss --> rax
 * @param ctype 要加载的数据类型
 * @param label 全局数组在.data or .bss中的标签
 * label中可以蕴含data段中数据的偏移量
 * 比如 a标签偏移4字节的数据的标签是 a+4
 */
static void emit_gload(Ctype *ctype, char *label)
{
    if (ctype->type == CTYPE_ARRAY)
    {
        emit("lea %s(%%rip), %%rax", label);
        return;
    }
    char *reg;
    int size = ctype_size(ctype);
    switch (size)
    {
    case 1:
        emit("xor %%rax, %%rax");
        reg = "al";
        break;
    case 4:
        emit("xor %%rax, %%rax");
        reg = "eax";
        break;
    case 8:
        reg = "rax";
        break;
    default:
        error("Unknown data size: %s: %d", ctype_to_string(ctype), size);
    }
    emit("mov %s(%%rip), %%%s", label, reg);
}

/**
 * @brief 局部数据加载，如果是数组，则仅加载数组首地址
 * @param ctype 要加载的数据类型
 * @param loff 要加载局部变量在栈中相对于rbp的偏移量
 * stack --> rax
 */
static void emit_lload(Ctype *ctype, int loff)
{
    /* 如果是数组，将最终根据偏移量计算得到的地址 加载到rax */
    if(ctype->type == CTYPE_ARRAY){
        emit("lea -%d(%%rbp), %%rax", loff);
        return;
    }
    /* 其他类型*/
    int size = ctype_size(ctype);
    switch (size)
    {
    case 1:
        emit("xor %%rax, %%rax");
        emit("mov -%d(%%rbp), %%al", loff);
        break;
    case 4:
        emit("xor %%rax, %%rax");
        emit("mov -%d(%%rbp), %%eax", loff);
        break;
    case 8:
        emit("mov -%d(%%rbp), %%rax", loff);
        break;
    default:
        error("Unknown data size: %s: %d", ctype_to_string(ctype), size);
    }
}

/**
 * rax --> .data or .bss
 * 将rax寄存器中的数据保存在data或bss段上相应的标签位置
 * @param ctype 要存放到data段的数据类型
 * @param label 全局变量在data或bss段上相应的标签位置，label+off可以代表全局偏移
 */
static void emit_gsave(Ctype *ctype, char *label)
{
    /* 数组类型的变量无法直接存放到data段中 */
    assert(ctype->type != CTYPE_ARRAY);
    char *reg;
    int size = ctype_size(ctype);
    switch (size)
    {
    case 1:
        reg = "al";
        break;
    case 4:
        reg = "eax";
        break;
    case 8:
        reg = "rax";
        break;
    default:
        error("Unknown data size: %s: %d", ctype_to_string(ctype), size);
    }
    emit("mov %%%s, %s(%%rip)", reg, label);
}

/**
 * 将局部变量存放在栈中
 * @param ctype 要保存的数据类型
 * @param loff 数据要保存在栈的基址
 * @param off 相对于栈基址偏移量，以ctype类型对应的大小为单位
 * rax --> stack
 */
static void emit_lsave(Ctype *ctype, int loff, int off)
{
    char *reg;
    int size = ctype_size(ctype);
    switch (size)
    {
    case 1:
        reg = "al";
        break;
    case 4:
        reg = "eax";
        break;
    case 8:
        reg = "rax";
        break;
    }
    emit("mov %%%s, -%d(%%rbp)", reg, loff + off * size);
}

/**
 * @brief 给解引用变量赋值
 * 例如：*a = 1
 * 此时要赋的值已经在rax中
 * @param var 解引用变量的抽象语法树，比如*a
 */
static void emit_assign_deref(Ast *var)
{
    /* 将rax里面要赋值的数据暂存在栈中 */
    emit("push %%rax");
    emit_expr(var->operand);
    emit("pop %%rcx");
    char *reg;
    int size = ctype_size(var->operand->ctype->ptr);
    switch (size)
    {
    case 1:
        reg = "cl";
        break;
    case 4:
        reg = "ecx";
        break;
    case 8:
        reg = "rcx";
        break;
    }
    emit("mov %%%s, (%%rax)", reg);
}

/**
 * 指针二元运算树 对应的代码产生方式
 * 因为指针运算需要考虑指针类型，所以特殊一点
 * 比如int *a; a + 2; 相当于一共偏移 2 * 4 = 8个字节，因为一个int类型是4字节
 * 指针只会进行 + - 操作
 */
static void emit_pointer_arithmetic(char op, Ast *left, Ast *right)
{
    /* 确保左子树是指针 or 数组类型 */
    assert(left->ctype->type == CTYPE_PTR || left->ctype->type == CTYPE_ARRAY);
    /* 如果左右子树都是指针类型 这个逻辑后续再理一理 */
    if (right->ctype->type == CTYPE_PTR)
    {
        /* 确保指针指向的类型一致 */
        /* 且指针之间只有做减法操作才有意义 */
        assert(left->ctype->ptr->type == right->ctype->ptr->type);
        if (op == '+')
            error("No meaning for ptr plus ptr");
        emit_expr(left);
        emit("push %%rax");
        emit_expr(right);
        int sft = ctype_shift(left->ctype->ptr);
        emit("mov %%rax, %%rbx");
        emit("pop %%rax");
        emit("sub %%rbx, %%rax");
        emit("sar $%d, %%rax", sft);
        return;
    }

    emit_expr(left);
    emit("push %%rax");
    emit_expr(right);
    /* 根据指针指向的类型，计算指针运算的单位大小 */
    int sz = ctype_size(left->ctype->ptr);
    if(sz > 1)
        emit("imul $%d, %%rax", sz);
    char *s = "add";
    if (op == '-')
        s = "sub";
    emit("mov %%rax, %%rbx");
    emit("pop %%rax");
    emit("%s %%rbx, %%rax", s);
}

// 待赋值的数据已经在rax中
static void emit_assign(Ast *var)
{
    if(var->type == AST_DEREF){
        emit_assign_deref(var);
        return;
    }
    switch (var->type)
    {
    case AST_LVAR:
        emit_lsave(var->ctype, var->loff, 0);
        break;
    case AST_GVAR:
        emit_gsave(var->ctype, var->glabel);
        break;
    default:
        error("internal error when assigning...");
    }
}

/** 
 * @brief 比较运算：>, <, ==
 * @param ins 指令
 */
static void emit_comp(char *inst, Ast *a, Ast *b){
    emit_expr(a);
    emit("push %%rax");
    emit_expr(b); // b -> rax
    emit("pop %%rcx"); // a -> rcx 
    emit("cmp %%rax, %%rcx"); // cmp b, a;
    emit("%s %%al", inst);
    emit("movzb %%al, %%rax");
}

/**
 * 二元运算树代码产生
 */
static void emit_binop(Ast *ast)
{
    // 如果是赋值语句
    if (ast->type == '=')
    {
        emit_expr(ast->right);
        emit_assign(ast->left);
        return;
    }
    if (ast->type == PUNCT_EQ) {
        emit_comp("sete", ast->left, ast->right);
        return;
    }
    // 如果二元运算树是指针类型
    if (ast->ctype->type == CTYPE_PTR)
    {
        emit_pointer_arithmetic(ast->type, ast->left, ast->right);
        return;
    }

    // 如果是计算表达式
    char *op;
    switch (ast->type)
    {
    case '<': 
        emit_comp("setl", ast->left, ast->right);
        return;
    case '>':
        emit_comp("setg", ast->left, ast->right);
        return;
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
        error("invalid operator '%d'", ast->type);
    }
    emit_expr(ast->left);
    emit("push %%rax");
    emit_expr(ast->right);
    emit("mov %%rax, %%rbx");
    emit("pop %%rax");
    if (ast->type == '/')
    {
        /* rdx存放余数 */
        /* rax存放商 */
        emit("mov $0, %%rdx");
        emit("idiv %%rbx");
    }
    else
    {
        emit("%s %%rbx, %%rax", op);
    }
}

void emit_expr(Ast *ast)
{
    switch (ast->type)
    {
    case AST_LITERAL:
        switch (ast->ctype->type)
        {
        case CTYPE_INT:
            emit("mov $%d, %%rax", ast->ival);
            break;
        case CTYPE_CHAR:
            emit("xor %%rax, %%rax");
            emit("mov $%d, %%al", ast->c);
            break;
        default:
            error("internal error");
        }
        break;
    case AST_STRING:
        emit("lea %s(%%rip), %%rax", ast->slabel);
        break;
    case AST_LVAR:
        emit_lload(ast->ctype, ast->loff);
        break;
    case AST_GVAR:
        emit_gload(ast->ctype, ast->glabel);
        break;
    case AST_FUNCALL:
        // 调用前 先将参数寄存器压栈，保存执行环境
        for (int i = 0; i < list_len(ast->args); i++)
        {
            emit("push %%%s", REGS[i]);
        }
        int j = 0;
        for (Iter *i = list_iter(ast->args); !iter_end(i); j++)
        {
            // 解析参数
            emit_expr(iter_next(i));
            emit("mov %%rax, %%%s", REGS[j]);
        }
        emit("mov $0, %%rax"); // 将rax初始化为0
        emit("call %s", ast->fname);
        // 调用后，恢复执行环境
        for (int i = list_len(ast->args) - 1; i >= 0; i--)
        {
            emit("pop %%%s", REGS[i]);
        }
        break;
    case AST_DECL:
        if(!ast->decl_init) return ;
        
        // array = {xxx, xxx, xxx}
        if (ast->decl_init->type == AST_ARRAY_INIT)
        {
            int j = 0;
            for (Iter *i = list_iter(ast->decl_init->array_init); !iter_end(i); j++)
            {
                emit_expr(iter_next(i));
                emit_lsave(get_array_element_ctype(ast->decl_var->ctype), ast->decl_var->loff, -j);
            }
        }
        // array = "xxxx"
        else if (ast->decl_var->ctype->type == CTYPE_ARRAY)
        {
            assert(ast->decl_init->type == AST_STRING);
            int i = 0;
            for (char *p = ast->decl_init->sval; *p; p++, i++)
                emit("movb $%d, -%d(%%rbp)", *p, ast->decl_var->loff - i);
            emit("movb $0, -%d(%%rbp)", ast->decl_var->loff - i);
        }
        // char *a = "xxxx"
        else if (ast->decl_init->type == AST_STRING)
        {
            emit_gload(ast->decl_init->ctype, ast->decl_init->slabel);
            emit_lsave(ast->decl_var->ctype, ast->decl_var->loff, 0);
        }
        // 其他declaration类型
        else
        {
            // 初始化值是变量表达式
            emit_expr(ast->decl_init);
            emit_lsave(ast->decl_var->ctype, ast->decl_var->loff, 0);
        }
        break;
    case AST_ADDR:
        /* 保证操作数是变量类型 */
        assert(ast->operand->type == AST_LVAR);
        /* 将变量在栈中存放地址放入rax */
        emit("lea -%d(%%rbp), %%rax", ast->operand->loff);
        break;
    case AST_DEREF:
        emit_expr(ast->operand);
        /* 访存，将值赋予rax */
        char *reg;
        switch (ctype_size(ast->ctype))
        {
        case 1:
            reg = "bl";
            break;
        case 4:
            reg = "ebx";
            break;
        default:
            reg = "rbx";
            break;
        }
        if(ast->operand->ctype->ptr->type != CTYPE_ARRAY){
            emit("xor %%rbx, %%rbx");
            emit("mov (%%rax), %%%s", reg);
            emit("mov %%rbx, %%rax");
        }
        break;
    case AST_IF:
        emit_expr(ast->cond);
        char *ne = make_next_label();
        emit("test %%rax, %%rax");
        emit("je %s", ne);
        emit_expr(ast->then);
        if(ast->els){ // exist else clause
            char *end = make_next_label();
            emit("jmp %s", end);
            // 下面开始时执行 else的部分
            emit_label("%s:", ne);
            emit_expr(ast->els);
            // 执行完else 之后，打上end标签
            emit_label("%s:", end);
        }else{
            emit_label("%s:", ne);
        }
        break;
    case AST_FOR:
        if(ast->forinit) emit_expr(ast->forinit);
        char *begin = make_next_label();
        char *end = make_next_label();
        emit_label("%s:", begin);
        if(ast->forcond){
            emit_expr(ast->forcond);
            emit("test %%rax, %%rax");
            emit("je %s", end);
        }
        emit_expr(ast->forbody);
        if(ast->forstep) emit_expr(ast->forstep);
        emit("jmp %s", begin);
        emit_label("%s:", end);
        break;
        
    case AST_COMPOUND_STMT:
        for(Iter *i = list_iter(ast->stmts);!iter_end(i); ){
            emit_expr(iter_next(i));
        }
        break;
    case PUNCT_DEC:
        emit_expr(ast->operand);
        emit("dec %%rax");
        emit_assign(ast->operand);
        break;
    case PUNCT_INC:
        emit_expr(ast->operand);
        emit("inc %%rax");
        emit_assign(ast->operand);
        break;
    case '!':
        emit_expr(ast->operand);
        emit("cmp $0, %%rax");
        // sete将ZF的值拷贝到 指定寄存器中
        emit("sete %%al");
        // movzb有符号扩展拷贝1字节
        emit("movzb %%al, %%rax");
        break;
    default:
        // 其他情况， 解析二元运算树
        emit_binop(ast);
    }
}

static void emit_data_section()
{
    if (!globals)
        return;
    emit(".data");
    for (Iter *i = list_iter(globals); !iter_end(i);)
    {
        Ast *p = iter_next(i);
        emit_label("%s:", p->slabel);
        if(p->type == AST_STRING){
            emit(".string \"%s\"", quote(p->sval));
        }
        // 目前支持字符串全局变量，TODO 支持其他全局变量
        else error("only string global data is available");
    }
}

// >= n 的最小的8的倍数
static int ceil8(int n)
{
    int rem = n % 8;
    return (rem == 0) ? n : n - rem + 8;
}

void print_asm_header(void)
{
    // 局部变量在栈中的总偏移量
    int off = 0;
    for (Iter *i = list_iter(locals); !iter_end(i);)
    {
        Ast *p = iter_next(i);
        off += ceil8(ctype_size(p->ctype));
        p->loff = off;
    }
    emit_data_section();
    printf(".text\n\t"
           ".global mymain\n"
           "mymain:\n\t"
           "push %%rbp\n\t"
           "mov %%rsp, %%rbp\n");
    if (locals->len)
        printf("\tsub $%d, %%rsp\n", off);
}