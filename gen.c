/*
 * @Author: QQYYHH
 * @Date: 2022-05-08 21:59:28
 * @LastEditTime: 2022-05-09 14:47:19
 * @LastEditors: QQYYHH
 * @Description: x64 code generate
 * @FilePath: /pwn/qcc/gen.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include "qcc.h"

// x64下函数前6个实参会依次放入下列寄存器
static char *REGS[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};

// ===================== emit ====================

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
 * 如果是数组或指针，则仅加载地址
 * .data or .bss --> rax
 * @off 如果是数组，将偏移为off的数组元素加载到rax中
 * @label 全局数组在.data or .bss中的标签
 */
static void emit_gload(Ctype *ctype, char *label, int off)
{
    if (ctype->type == CTYPE_ARRAY)
    {
        printf("lea %s(%%rip), %%rax\n\t", label);
        // 由于不确定数组元素的类型，这里仅将元素地址传到rax中
        if (off)
            printf("add $%d, %%rax\n\t", ctype_size(ctype->ptr) * off);
        return;
    }
    char *reg;
    int size = ctype_size(ctype);
    printf("xor %%rax, %%rax\n\t");
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
    printf("mov %s(%%rip), %%%s\n\t", label, reg);
    // 如果off不为0，说明当前 ctype->type == CTYPE_PTR
    // 要加上 以指针指向类型为单位 的偏移量
    // TODO 处理逻辑
    if (off)
    {
        printf("add $%d, %%rax\n\t", off * ctype_size(ctype->ptr));
    }
}

/**
 * 局部数据加载
 * 如果是指针或数组，则仅加载地址
 * stack --> rax
 */
static void emit_lload(Ast *var, int off)
{
    if (var->ctype->type == CTYPE_ARRAY)
    {
        printf("lea -%d(%%rbp), %%rax\n\t", var->loff);
        if (off)
            printf("add $%d, %%rax\n\t", ctype_size(var->ctype->ptr) * off);
        return;
    }
    int size = ctype_size(var->ctype);
    printf("xor %%rax, %%rax\n\t");
    switch (size)
    {
    case 1:
        printf("mov -%d(%%rbp), %%al\n\t", var->loff);
        break;
    case 4:
        printf("mov -%d(%%rbp), %%eax\n\t", var->loff);
        break;
    case 8:
        printf("mov -%d(%%rbp), %%rax\n\t", var->loff);
        break;
    default:
        error("Unknown data size: %s: %d", ast_to_string(var), size);
    }
    // 如果是指针变量
    if (off)
        printf("add $%d, %%rax\n\t", off * ctype_size(var->ctype->ptr));
}

/**
 * rax --> .data or .bss
 * 将rax寄存器中的数据保存在data或bss段上相应的标签位置
 */
static void emit_gsave(Ast *var, int off)
{
    assert(var->ctype->type != CTYPE_ARRAY);
    char *reg;
    printf("push %%rbx\n\t");
    // 下面问题很大
    printf("mov %s(%%rip), %%rbx\n\t", var->glabel);
    int size = ctype_size(var->ctype);
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
        error("Unknown data size: %s: %d", ast_to_string(var), size);
    }
    printf("mov %s, %d(%%rbp)\n\t", reg, off * size);
    printf("pop %%rbx\n\t");
}

/**
 * 将局部变量存放在栈中
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
    printf("mov %%%s, -%d(%%rbp)\n\t", reg, loff + off * size);
}

/**
 * 指针二元运算树 对应的代码产生方式
 * 因为指针运算需要考虑指针类型，所以特殊一点
 * 比如int *a; a + 2; 相当于一共偏移 2 * 4 = 8个字节，因为一个int类型是4字节
 * 指针只会进行 + - 操作
 */
static void emit_pointer_arithmetic(char op, Ast *left, Ast *right)
{
    /* 确保左子树是指针类型 */
    assert(left->ctype->type == CTYPE_PTR);
    /* 如果左右子树都是指针类型 */
    if (right->ctype->type == CTYPE_PTR)
    {
        /* 确保指针指向的类型一致 */
        /* 且指针之间只有做减法操作才有意义 */
        assert(left->ctype->ptr->type == right->ctype->ptr->type);
        if (op == '+')
            error("No meaning for ptr plus ptr");
        emit_expr(left);
        printf("push %%rax\n\t");
        emit_expr(right);
        int sft = ctype_shift(left->ctype->ptr);
        printf("mov %%rax, %%rbx\n\t"
               "pop %%rax\n\t"
               "sub %%rbx, %%rax\n\t"
               "sar $%d, %%rax\n\t",
               sft);
        return;
    }

    emit_expr(left);
    printf("push %%rax\n\t");
    emit_expr(right);
    /* 根据指针指向的类型，计算偏移量 */
    int sft = ctype_shift(left->ctype->ptr);
    if (sft > 0)
        /* sal 有符号左移动 */
        printf("sal $%d, %%rax\n\t", sft);
    char *s = "add";
    if (op == '-')
        s = "sub";
    printf("mov %%rax, %%rbx\n\t"
           "pop %%rax\n\t"
           "%s %%rbx, %%rax\n\t",
           s);
}

static void emit_assign(Ast *var, Ast *value)
{
    emit_expr(value);
    switch (var->type)
    {
    case AST_LVAR:
        emit_lsave(var->ctype, var->loff, 0);
        break;
    case AST_LREF:
        emit_lsave(var->lref->ctype, var->lref->loff, var->lrefoff);
        break;
    case AST_GVAR:
        emit_gsave(var, 0);
        break;
    case AST_GREF:
        emit_gsave(var->gref, var->grefoff);
        break;
    default:
        error("internal error when assigning...");
    }
}

/**
 * 二元运算树代码产生
 */
static void emit_binop(Ast *ast)
{
    // 如果是赋值语句
    if (ast->type == '=')
    {
        emit_assign(ast->left, ast->right);
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
        /* rdx存放余数 */
        /* rax存放商 */
        printf("mov $0, %%rdx\n\t");
        printf("idiv %%rbx\n\t");
    }
    else
    {
        printf("%s %%rbx, %%rax\n\t", op);
    }
}

void emit_expr(Ast *ast)
{
    switch (ast->type)
    {
    case AST_LITERAL:
        printf("xor %%rax, %%rax\n\t");
        switch (ast->ctype->type)
        {
        case CTYPE_INT:
            printf("mov $%d, %%rax\n\t", ast->ival);
            break;
        case CTYPE_CHAR:
            printf("mov $%d, %%al\n\t", ast->c);
            break;
        default:
            error("internal error");
        }
        break;
    case AST_STRING:
        printf("lea %s(%%rip), %%rax\n\t", ast->slabel);
        break;
    case AST_LVAR:
        emit_lload(ast, 0);
        break;
    case AST_LREF:
        // 必须引用局部变量
        assert(ast->lref->type == AST_LVAR);
        emit_lload(ast->lref, ast->lrefoff);
        break;
    case AST_GVAR:
        emit_gload(ast->ctype, ast->glabel, 0);
        break;
    case AST_GREF:
        if (ast->gref->type == AST_STRING)
        {
            printf("lea %s(%%rip), %%rax\n\t", ast->gref->slabel);
        }
        else
        {
            assert(ast->gref->type == AST_GVAR);
            emit_gload(ast->gref->ctype, ast->gref->glabel, ast->grefoff);
        }
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
    case AST_DECL:
        if (ast->decl_init->type == AST_ARRAY_INIT)
        {
            for (int i = 0; i < ast->decl_init->size; i++)
            {
                emit_expr(ast->decl_init->array_init[i]);
                emit_lsave(ast->decl_var->ctype->ptr, ast->decl_var->loff, -i);
            }
        }
        else if (ast->decl_var->ctype->type == CTYPE_ARRAY)
        {
            assert(ast->decl_init->type == AST_STRING);
            int i = 0;
            for (char *p = ast->decl_init->sval; *p; p++, i++)
                printf("movb $%d, -%d(%%rbp)\n\t", *p, ast->decl_var->loff - i);
            printf("movb $0, -%d(%%rbp)\n\t", ast->decl_var->loff - i);
        }
        else if (ast->decl_init->type == AST_STRING)
        {
            emit_gload(ast->decl_init->ctype, ast->decl_init->slabel, 0);
            emit_lsave(ast->decl_var->ctype, ast->decl_var->loff, 0);
        }
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
        printf("lea -%d(%%rbp), %%rax\n\t", ast->operand->loff);
        break;
    case AST_DEREF:
        /* 保证操作数是指针 */
        assert(ast->operand->ctype->type == CTYPE_PTR);
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
        case 8:
            reg = "rbx";
            break;
        default:
            error("interal error");
        }
        printf("xor %%rbx, %%rbx\n\t");
        printf("mov (%%rax), %%%s\n\t", reg);
        printf("mov %%rbx, %%rax\n\t");
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
    printf("\t.data\n");
    for (Ast *p = globals; p; p = p->next)
    {
        assert(p->type == AST_STRING);
        printf("%s:\n\t", p->slabel);
        printf(".string \"%s\"\n", quote(p->sval));
    }
    printf("\t");
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
    for (Ast *p = locals; p; p = p->next)
    {
        off += ceil8(ctype_size(p->ctype));
        p->loff = off;
    }
    emit_data_section();
    printf(".text\n\t"
           ".global mymain\n"
           "mymain:\n\t"
           "push %%rbp\n\t"
           "mov %%rsp, %%rbp\n\t");
    if (locals)
        printf("sub $%d, %%rsp\n\t", off);
}