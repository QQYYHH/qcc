<!--
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:42:47
 * @LastEditTime: 2022-05-03 21:14:37
 * @LastEditors: QQYYHH
 * @Description: 
 * @FilePath: /pwn/qcc/README.md
 * welcome to my github: https://github.com/QQYYHH
-->
# qcc
这可能是一个支持c11的编译器，从0开始写，最终能够做到自己编译自己
参考 8cc
https://github.com/rui314/8cc/commits/master?before=b480958396f159d3794f0d4883172b21438a8597+766&branch=master<br>


## TODO
- [x] 加减乘除混合运算
- [x] 变量赋值语句
- [x] add function call
- [x] add char
- [x] abstract part of code as lexer
- [x] add declaration
- [x] add type checking
- [x] add pointer, unary operator
- [ ] add array
- [ ] distinguish global/local vars

## issue
- "int a =2; int \*b = &a; \*b = 3; \*b"，暂时无法对\*b这种 通过指针访问的内存区域赋值

## bug fix
- 赋值语句中 `=` 的优先级比较特殊，对于连续的`=`，前面的优先级 < 后面；对于+ - * / 来说，相同符号前面的优先级 > 后面