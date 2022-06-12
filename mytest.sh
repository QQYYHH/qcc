#!/bin/bash
###
 # @Author: QQYYHH
 # @Date: 2022-04-10 21:13:06
 # @LastEditTime: 2022-06-12 23:00:54
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

function testastf {
  result="$(echo "$2" | ./qcc -p)"
  if [ $? -ne 0 ]; then
    echo "Failed to compile $2"
    exit
  fi
  assertequal "$result" "$1"
  echo "[*] success on expr: $1"
}

function testast {
  testastf "$1" "int f(){$2}"
}

function testf {
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

function test {
  testf "$1" "int f() { $2 }"
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
testast '(int)f(){1;}' '1;'
testast '(int)f(){(+ (- (+ 1 2) 3) 4);}' '1+2-3+4;'
testast '(int)f(){(+ (+ 1 (* 2 3)) 4);}' '1+2*3+4;'
testast '(int)f(){(+ (* 1 2) (* 3 4));}' '1*2+3*4;'
testast '(int)f(){(+ (/ 4 2) (/ 6 3));}' '4/2+6/3;'
testast '(int)f(){(/ (/ 24 2) 4);}' '24/2/4;'
testast '(int)f(){(decl int a 3);}' 'int a=3;'
testast "(int)f(){(decl char c 'a');}" "char c='a';"
testast '(int)f(){(decl char* s "abcd");}' 'char *s="abcd";'
testast '(int)f(){(decl [5]char s "asdf");}' 'char s[5]="asdf";'
testast '(int)f(){(decl [5]char s "asdf");}' 'char s[]="asdf";'
testast '(int)f(){(decl [3]int a {1,2,3});}' 'int a[3]={1,2,3};'
testast '(int)f(){(decl [3]int a {1,2,3});}' 'int a[]={1,2,3};'
testast '(int)f(){(decl [3][5]int a);}' 'int a[3][5];'
testast '(int)f(){(decl [5]int* a);}' 'int *a[5];'
testast '(int)f(){(decl int a 1);(decl int b 2);(= a (= b 3));}' 'int a=1;int b=2;a=b=3;'
testast '(int)f(){(decl int a 3);(& a);}' 'int a=3;&a;'
testast '(int)f(){(decl int a 3);(* (& a));}' 'int a=3;*&a;'
testast '(int)f(){(decl int a 3);(decl int* b (& a));(* b);}' 'int a=3;int *b=&a;*b;'
testast '(int)f(){(if 1 {2;});}' 'if(1){2;}'
testast '(int)f(){(if 1 {2;} {3;});}' 'if(1){2;}else{3;}'
testast '(int)f(){(for (decl int a 1) 3 7 {5;});}' 'for(int a=1;3;7){5;}'
testast '(int)f(){"abcd";}' '"abcd";'
testast "(int)f(){'c';}" "'c';"
testast '(int)f(){(int)a();}' 'a();'
testast '(int)f(){(int)a(1,2,3,4,5,6);}' 'a(1,2,3,4,5,6);'
testast '(int)f(){(return 1);}' 'return 1;'
testast '(int)f(){(< 1 2);}' '1<2;'
testast '(int)f(){(> 1 2);}' '1>2;'
testast '(int)f(){(== 1 2);}' '1==2;'
testast '(int)f(){(* (+ 1 2));}' '1[2];'
testast '(int)f(){(decl int a 1);(++ a);}' 'int a=1;a++;'
testast '(int)f(){(decl int a 1);(-- a);}' 'int a=1;a--;'
testast '(int)f(){(! 1);}' '!1;'

# Expression
# Basic arithmetic
test 5 "1+2 * 3 - 4 / 2;"
test 0 '0;'
test 3 '1+2;'
test 3 '1 + 2;'
test 10 '1+2+3+4;'
test 11 '1+2*3+4;'
test 14 '1*2+3*4;'
test 4 '4/2+6/3;'
test 3 '24/2/4;'
test 98 "'a'+1;"
test 2 '1;2;'
# add brackets ( )
test 9 '(1 + 2) * 3;'

# Comparision
test 1 '1<2;'
test 0 '2<1;'
test 1 '1==1;'
test 0 '1==2;'

# Declaration
test 1 "int a = 1;"
test 3 "int a = 1; int b = a + 2;"
test 10 'int a = 1 ; int  b = a * 2 + 2 / 3 ; int c=2 * a+b;c * 2 + 5 / 2;'
test 55 'int a[]={55};int *b=a;*b;'
test 67 'int a[]={55,67};int *b=a+1;*b;'
test 30 'int a[]={20,30,40};int *b=a+1;*b;'
test 20 'int a[]={20,30,40};*a;'

# Function Call
test 21 "int a = 1; int b = a + 1; int c = b + 1; int d = c + 1; int e = d + 1; int f = e  +1; sum6(a,b,c,d,e,f);"
testfail "sum2(1, 2,);"
test -1 "sub2(1, 2);"
test "abc\"3" 'printf("abc\"");3;'
test "the character is: b2" "printf(\"the character is: %c\", 'a' + 1);2;"
test "hello_worldxxxxxxxx b xxxxx3" "int a = \"hello_worldxxxxxxxx %c xxxxx\"; printf(a, 'b');3;"

# Pointer
test 61 'int a=61;int *b=&a;*b;'
test 2 "int a =2; int *b = &a; int **c = &b; **c;"
test 23 "int a = 2; int *b = &a; int **c = &b; printf(\"%d\", **c);3;"
test 97 'char *c="ab";*c;'
test 98 'char *c="ab"+1;*c;'
test 'pointer difference is: 1777' 'int a = 1; int *b = &a; int *c = b + 1; printf("pointer difference is: %d",c - b);777;'
test 99 'char s[4]="abc";char *c=s+2;*c;'

# Array
test 1 'int a[3]={20, 30, 40}; *(a + 1) = 1;a[1];'
# support expr in array size
test 1 'int a[1 + 1][1 + 2];int *p=a;*p=1;*p;'
test 32 'int a[2][3];int *p=a+1;*p=1;int *q=a;*p=32;*(q+3);'
test 62 'int a[4][5];int *p=a;*(*(a+1)+2)=62;*(p+7);'
test '1 2 3 0' 'int a[3]={1,2,3};printf("%d %d %d ",a[0],a[1],a[2]);0;'
test '1 2 0' 'int a[2][3];a[0][1]=1;a[1][1]=2;int *p=a;printf("%d %d ",p[1],p[4]);0;'
test 7 'int a[1][2]; a[0 * 0][1 + 2 - 2] = 2; a[0][0] = 5 ;a[0][1] + a[0][0];'
test 122 'char s[]="xyz";char *c=s+2;*c;'
test 65 'char s[]="xyz";*s=65;*s;'
test 4 'int a[2][3] = {0, 1, 2, 3, 4, 5}; a[1][1];'

# IF
test 'a1' 'if(1){printf("a");}1;'
test '1' 'if(0){printf("a");}1;'
test 'x1' 'if(1){printf("x");}else{printf("y");}1;'
test 'y1' 'if(0){printf("x");}else{printf("y");}1;'
test 'a1' 'if(1)printf("a");1;'
test '1' 'if(0)printf("a");1;'
test 'x1' 'if(1)printf("x");else printf("y");1;'
test 'y1' 'if(0)printf("x");else printf("y");1;'
test 1 '{{{{{{{{{{1;}}}}}}}}}}'

# Increment or decrement
test 16 'int a=15;a++;'
test 16 'int a=15;a++;a;'
test 14 'int a=15;a--;'
test 14 'int a=15;a--;a;'


# Boolean operators
test 0 '!1;'
test 1 '!0;'
test 2 '!15 + 2;'
test 0 '!(15 + 2);'
test 1 '!!15;'
test 1 'int *a[3]; int b = 2; a[0] = &b; !!**a;'

# For statement
test 012340 'for(int i=0; i<5; i=i+1){printf("%d",i);}0;'

# Type Cast
test 0 'char a = 256;a;'

# Incompatible type
# testfail '"a"+1;'
# & is only applicable when operand is variable
testfail '&"a";'
testfail '&1;'
testfail '&a();'
testfail '&&a;'

# Function parameter
testastf '(int)f(int c){c;}' 'int f(int c){c;}'
testastf '(int)f(int c){c;}(int)g(int d){d;}' 'int f(int c){c;} int g(int d){d;}'
testastf '(decl int a 3)' 'int a=3;'
testf 77 'int g(){return 77;} int f(){g();}' 
testf 79 'int g(int a){return a;} int f(){g(79);}'
testf 21 'int g(int a,int b,int c,int d,int e,int f){return a+b+c+d+e+f;} int f(){g(1,2,3,4,5,6);}'
testf 79 'int g(int a){return a;} int f(){g(79);}'
testf 98 'int g(int *p){return *p;} int f(){int a[]={98};g(a);}'
testf '99 98 97 1' 'int g(int *p){for(int i = 0; i < 3; i++) { printf("%d ",*p);p=p+1; } 1;} int f(){int a[]={1,2,3};int *p=a;*p=99;p=p+1;*p=98;p=p+1;*p=97;g(a);}'

# Global variable
testf 21 'int a=21;int f(){a;}'
testf 22 'int a;int f(){a=22;a;}'
testf 23 'int a[3];int f(){a[1]=23;a[1];}'
testf 25 'int a[3]={24,25,26};int f(){a[1];}'
testf 195 'char *a = "abc";int f(){a[0] + a[1];}' 
testf 195 'char a[] = "abc"; int f() { a[0] + a[1]; }'

echo "All tests passed"
make clean


# s='int a = 1; int *b = &a; int *c = b + 1; printf("pointer difference is: %d",c - b);777;'
# echo "$s" | ./qcc
# compile "$s"