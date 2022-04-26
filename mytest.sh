#!/bin/bash
###
 # @Author: QQYYHH
 # @Date: 2022-04-10 21:13:06
 # @LastEditTime: 2022-04-26 16:13:04
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

function assertequal {
  if [ "$1" != "$2" ]; then
    echo "Test failed: $2 expected but got $1"
    exit
  fi
}

function testast {
  result="$(echo "$2" | ./qcc -p)"
  if [ $? -ne 0 ]; then
    echo "Failed to compile $2"
    exit
  fi
  assertequal "$result" "$1"
  echo "[*] success on expr: $1"
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
# make -s qcc
make qcc
# Parser
testast '1' '1;'
testast '(+ (- (+ 1 2) 3) 4)' '1+2-3+4;'
testast '(+ (+ 1 (* 2 3)) 4)' '1+2*3+4;'
testast '(+ (* 1 2) (* 3 4))' '1*2+3*4;'
testast '(+ (/ 4 2) (/ 6 3))' '4/2+6/3;'
testast '(/ (/ 24 2) 4)' '24/2/4;'
testast '(decl int a 3)' 'int a=3;'
testast "(decl char c 'a')" "char c='a';"
testast '(decl int a 1)(decl int b 2)(= a (= b 3))' 'int a=1;int b=2;a=b=3;'
testast '"abc"' '"abc";'
testast "'c'" "'c';"
testast 'a()' 'a();'
testast 'a(1,2,3,4,5,6)' 'a(1,2,3,4,5,6);'

# Expression
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

# Incompatible type
testfail '"a"+1;'

echo "All tests passed"
# s="int a = 1; int b = a + 2;"
# echo "$s" | ./qcc
# compile "$s"