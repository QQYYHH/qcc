/*
 * @Author: QQYYHH
 * @Date: 2022-04-26 15:53:58
 * @LastEditTime: 2022-06-13 16:54:46
 * @LastEditors: QQYYHH
 * @Description: 
 * @FilePath: /pwn/qcc/util.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include "qcc.h"

#define TAB 8
void errorf(char *file, int line, char *fmt, ...) {
  fprintf(stderr, "%s:%d: ", file, line);
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
  exit(1);
}

// void warn(char *fmt, ...){
//   fprintf(stderr, "warning: ");
//   va_list args;
//   va_start(args, fmt);
//   vfprintf(stderr, fmt, args);
//   fprintf(stderr, "\n");
//   va_end(args);
// }

void emitf(int line, char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  int col = vprintf(fmt, args);
  va_end(args);

  for (char *p = fmt; *p; p++)
    if (*p == '\t')
      col += TAB - 1;
  int space = (30 - col) > 0 ? (30 - col) : 2;
  printf("%*c %d\n", space, '#', line);
}

char *quote(char *p)
{
    String *s = make_string();
    while (*p)
    {
        if (*p == '\"' || *p == '\\') string_appendf(s, "\\%c", *p);
        else if(*p == '\n') string_appendf(s, "\\n");
        else if(*p == '\t') string_appendf(s, "\\t");
        else string_append(s, *p);
        p++;
    }
    return get_cstring(s);
}

// 模拟执行抽象语法树，得到最终的运算结果
int emulate_cal(Ast *ast){
  assert(ast->ctype->type == CTYPE_INT);
  if(ast->type == AST_LITERAL) return ast->ival;
  int left = emulate_cal(ast->left);
  int right = emulate_cal(ast->right);
  int ans = 0;
  switch(ast->type){
    case '+': ans = left + right; break;
    case '-': ans = left - right; break;
    case '*': ans = left * right; break;
    case '/': ans = (int)left / right; break;
    default: error("invalid operator '%c'", ast->type);
  }
  return ans;
}