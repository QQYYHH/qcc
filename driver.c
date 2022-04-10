/*
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:53:55
 * @LastEditTime: 2022-04-10 16:37:47
 * @LastEditors: QQYYHH
 * @Description: 用于测试主函数
 * @FilePath: /pwn/compiler/driver.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
/**
 * weak 代表弱符号类型，类似于C++中的重载
 * 如果外部有定义强符号类型的同名函数，则优先调用外部函数
 */
#define WEAK __attribute__((weak))
extern int intfn(void) WEAK;
extern char *stringfn(void) WEAK;

int main(int argc, char **argv)
{
    if (intfn)
    {
        printf("%d\n", intfn());
    }
    else if (stringfn)
    {
        printf("%s\n", stringfn());
    }
    else
    {
        printf("Should not happen");
    }
    return 0;
}