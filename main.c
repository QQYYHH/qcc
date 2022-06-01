/*
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:48:11
 * @LastEditTime: 2022-05-22 00:44:14
 * @LastEditors: QQYYHH
 * @Description: 主函数
 * @FilePath: /pwn/qcc/main.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "qcc.h"

// 最大表达式的数量
#define EXPR_LEN 100

int main(int argc, char **argv)
{
    int want_ast_tree = (argc > 1 && !strcmp("-p", argv[1]));
    Ast *exprs[EXPR_LEN];
    int i;
    for (i = 0; i < EXPR_LEN; i++)
    {
        Ast *ast = parse_decl_or_stmt();
        if (!ast)
            break;
        exprs[i] = ast;
    }
    int nexpr = i;
    if (!want_ast_tree)
        print_asm_header();

    for (i = 0; i < nexpr; i++)
    {
        if (want_ast_tree)
            printf("%s", ast_to_string(exprs[i]));
        else
            emit_expr(exprs[i]);
    }
    if (!want_ast_tree)
    {
        // 栈平衡
        printf("\tleave\n"
               "\tret");
    }
    printf("\n");
    return 0;
}
