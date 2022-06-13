#!/bin/bash
###
 # @Author: QQYYHH
 # @Date: 2022-04-10 14:55:11
 # @LastEditTime: 2022-06-13 16:58:55
 # @LastEditors: QQYYHH
 # @Description: 测试整个源文件作为输入
 # @FilePath: /pwn/qcc/test_file.sh
 # welcome to my github: https://github.com/QQYYHH
### 

function compile {
  ./qcc < "$1" > tmp.s
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
  file="$2"

  compile "$file"
  result="`./tmp.out`"
  if [ "$result" != "$expected" ]; then
    echo "Test failed: $expected expected but got $result"
    exit
  fi
  echo "[*] success on file $2"
}


# -s 不输出执行过的命令，silence模式
make -s qcc

test 8 test/fibo.c
compile test/nqueen.c
