#!/bin/bash
###
 # @Author: QQYYHH
 # @Date: 2022-04-10 21:13:06
 # @LastEditTime: 2022-04-25 17:26:53
 # @LastEditors: QQYYHH
 # @Description: 
 # @FilePath: /pwn/qcc/mytest.sh
 # welcome to my github: https://github.com/QQYYHH
### 

function compile {
  echo "$1" | ./qcc > tmp.s
  if [ $? -ne 0 ]; then
    echo "Failed to compile $1"
    exit
  fi
  gcc -o tmp.out driver.c tmp.s
  if [ $? -ne 0 ]; then
    echo "GCC failed"
    exit
  fi
}


function test {
  expected="$1"
  expr="$2"

  compile "$expr"
  result="`./tmp.out`"
  if [ "$result" != "$expected" ]; then
    echo "Test failed: $expected expected but got $result"
    exit
  fi
  echo "[*] success on expr: $expr"
}

function testfail {
  expr="$1"
  echo "$expr" | ./qcc > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "Should fail to compile, but succeded: $expr"
    exit
  fi
  echo "[*] success on expr: $expr"
}

# -s 不输出执行过的命令，silence模式
make -s qcc
# compile "$1"
test 5 "1+2 * 3 - 4 / 2;"
test 1 "int a = 1;"
test 3 "int a = 1; int b = a + 2;"
test 10 'int a = 1 ; int  b = a * 2 + 2 / 3 ; int c=2 * a+b;c * 2 + 5 / 2;'
test 21 "int a = 1; int b = a + 1; int c = b + 1; int d = c + 1; int e = d + 1; int f = e  +1; sum6(a,b,c,d,e,f);"
testfail "sum2(1, 2,);"
test -1 "sub2(1, 2);"
test "abc\"3" 'printf("abc\"");3;'
test "the character is: b2" "printf(\"the character is: %c\", 'a' + 1);2;"
test "hello_worldxxxxxxxx b xxxxx3" "int a = \"hello_worldxxxxxxxx %c xxxxx\"; printf(a, 'b');3;"
# s="int a = 1; int b = a + 2;"
# echo "$s" | ./qcc
# compile "$s"