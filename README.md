<!--
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:42:47
 * @LastEditTime: 2022-06-04 13:03:48
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
- [x] support brackets ( )
- [x] 变量赋值语句
- [x] add function call
- [x] add char
- [x] abstract part of code as lexer
- [x] add declaration
- [x] add type checking
- [x] add pointer, unary operator
- [x] pointer arithmetic
- [x] add array
- [x] array arithmetic
- [x] support multi-array
- [ ] distinguish global/local vars
- [x] split main into parser.c and gen.c
- [x] add list structure
- [ ] add bool and compare calculation
- [x] add if
- [x] add for 
- [ ] add func definition and return

## issue
- 没有测试 局部变量和全局变量运算及其赋值
- 多维数组 要以多重指针的方式存储

## bug fix
- 赋值语句中 `=` 的优先级比较特殊，对于连续的`=`，前面的优先级 < 后面；对于+ - * / 来说，相同符号前面的优先级 > 后面
- a[1] = 1 这种赋值方式已经支持
- 支持 使用表达式定义数组大小
- 修复多维数组初始化赋值的bug: a[2][3] = {0, 1, 2, 3,4 ,5}

## insight
解析数组元素分成两个核心步骤，比如a[2]，解析为*(a + 2)：
- 指针运算
- 解引用
