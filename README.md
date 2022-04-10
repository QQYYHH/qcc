<!--
 * @Author: QQYYHH
 * @Date: 2022-04-10 14:42:47
 * @LastEditTime: 2022-04-10 21:44:30
 * @LastEditors: QQYYHH
 * @Description: 
 * @FilePath: /pwn/compiler/README.md
 * welcome to my github: https://github.com/QQYYHH
-->
# qcc
这可能是一个支持c11的编译器，从0开始写，最终能够做到自己编译自己
参考 8cc
https://github.com/rui314/8cc/commits/master?before=b480958396f159d3794f0d4883172b21438a8597+766&branch=master<br>
从第一个commit入手

## Done
引入简单AST，可以实现+ - 混合运算
## TODO
加减乘除混合运算
Added * and /