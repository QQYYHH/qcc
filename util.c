/*
 * @Author: QQYYHH
 * @Date: 2022-04-26 15:53:58
 * @LastEditTime: 2022-05-20 13:32:46
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
        if (*p == '\"' || *p == '\\')
            string_append(s, '\\');
        string_append(s, *p);
        p++;
    }
    return get_cstring(s);
}