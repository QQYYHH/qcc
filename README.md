<!--
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:42:47
 * @LastEditTime: 2022-04-26 16:15:23
 * @LastEditors: QQYYHH
 * @Description: 
 * @FilePath: /pwn/qcc/README.md
 * welcome to my github: https://github.com/QQYYHH
-->
# qcc
这可能是一个支持c11的编译器，从0开始写，最终能够做到自己编译自己
参考 8cc
https://github.com/rui314/8cc/commits/master?before=b480958396f159d3794f0d4883172b21438a8597+766&branch=master<br>

## Done
完善表达式：
- 加减乘除混合运算
- 变量赋值语句
- add function call
- add char
- split qcc.c to main.c lexer.c and string.c
- add declaration
- add type checking 

## TODO
- [x] reintroduce string
- [x] add char
- [x] abstract part of code as lexer
- [x] add declaration
- [x] add type checking
- [ ] add pointer

## bug fix
- 赋值语句中 `=` 的优先级比较特殊，相同符号前面的优先级 < 后面；对于+ - * / 来说，相同符号前面的优先级 > 后面