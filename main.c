/*
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:48:11
 * @LastEditTime: 2022-06-01 20:07:03
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
    List *exprs = make_list();
    for (int i = 0; i < EXPR_LEN; i++)
    {
        Ast *ast = parse_decl_or_stmt();
        if (!ast)
            break;
        list_append(exprs, ast);
    }
    if (!want_ast_tree)
        print_asm_header();

    for (Iter *i = list_iter(exprs); !iter_end(i);)
    {
        Ast *ast = iter_next(i);
        if (want_ast_tree)
            printf("%s", ast_to_string(ast));
        else
            emit_expr(ast);
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
