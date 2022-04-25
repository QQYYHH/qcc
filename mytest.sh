#!/bin/bash
###
 # @Author: QQYYHH
 # @Date: 2022-04-10 21:13:06
 # @LastEditTime: 2022-04-25 15:18:20
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
}

function testfail {
  expr="$1"
  echo "$expr" | ./qcc > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "Should fail to compile, but succeded: $expr"
    exit
  fi
}

# -s 不输出执行过的命令，silence模式
make -s qcc
# compile "$1"
s="1+2 * 3 - 4 / 2;"
s='a=1 ; b = a * 2 + 2 / 3 ; c=2 * a+b;c * 2 + 5 / 2;' # 10
# s="a = 1; b = a + 1; c = b + 1; d = c + 1; e = d + 1; f = e  +1; sum6(a,b,c,d,e,f);" # 21
# s="sum2(1, 2,);"
# s="sub2(1, 2);"
# s='printf("abc\"");3;'
# s="printf(\"the character is: %c\", 'a' + 1);2;"
# s=" 'a2' ;"
s="a = \"hello_worldxxxxxxxx %c xxxxx\"; printf(a, 'b');"
echo "$s" | ./qcc
compile "$s"