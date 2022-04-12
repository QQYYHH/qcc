#!/bin/bash

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
# s="1 + 2 * 3;"
s='a=1 ; b = a * 2 + 2 / 3 ; c=2 * a+b;c * 2 + 5 / 2;'
echo "$s" | ./qcc
compile "$s"