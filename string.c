/*
 * @Author: QQYYHH
 * @Date: 2022-04-25 14:50:25
 * @LastEditTime: 2022-04-25 14:59:07
 * @LastEditors: QQYYHH
 * @Description: 实现类似vector的String类
 * @FilePath: /pwn/qcc/string.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "qcc.h"

#define INIT_SIZE 8

String *make_string(){
  String *r = malloc(sizeof(String));
  r->body = malloc(INIT_SIZE);
  r->nalloc = INIT_SIZE;
  r->len = 0;
  r->body[0] = '\0';
  return r;
}

static void realloc_body(String *s){
    int newsize = (s->nalloc << 1);
    s->body = realloc(s->body, newsize);
    s->nalloc = newsize;
}

char *get_cstring(String *s){
    return s->body;
}

void string_append(String *s, char c) {
  if (s->nalloc == (s->len + 1))
    realloc_body(s);
  s->body[s->len++] = c;
  s->body[s->len] = '\0';
}

void string_appendf(String *s, char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  for (;;) {
    int avail = s->nalloc - s->len;
    int written = vsnprintf(s->body + s->len, avail, fmt, args);
    if (avail <= written) {
      realloc_body(s);
      continue;
    }
    s->len += written + 1;
    return;
  }
}