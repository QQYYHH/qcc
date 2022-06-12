/*
 * @Author: QQYYHH
 * @Date: 2022-06-12 17:31:05
 * @LastEditTime: 2022-06-12 18:30:50
 * @LastEditors: QQYYHH
 * @Description: 
 * @FilePath: /pwn/qcc/test.c
 * welcome to my github: https://github.com/QQYYHH
 */
#include <stdio.h>
#include <stdlib.h>

char *a = "123";
char b[] = "456";
int c[][2] = {{10, 11}, {12, 13}, {14, 15}};
void fun1(){
    puts("fun1");
}
int d = 5;
int main(){
    printf("%c %c %d\n", a[1], b[2], c[2][1]);
    return 0;
}