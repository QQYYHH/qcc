/*
 * @Author: QQYYHH
 * @Date: 2022-06-01 18:13:16
 * @LastEditTime: 2022-06-01 19:43:36
 * @LastEditors: QQYYHH
 * @Description: list structure implement
 * @FilePath: /pwn/qcc/list.c
 * welcome to my github: https://github.com/QQYYHH
 */
#include <stdlib.h>
#include "qcc.h"

List *make_list(void){
    List *r = malloc(sizeof(List));
    r->len = 0;
    r->head = r->tail = NULL;
    return r;
}

static ListNode *make_node(void *elem){
    ListNode *ld = malloc(sizeof(ListNode));
    ld->elem = elem;
    ld->next = NULL;
    return ld;
}

void list_append(List *list, void *elem){
    ListNode *node = make_node(elem);
    if(!list->head) list->head = node;
    else list->tail->next = node;
    list->tail = node;
    list->len++;
}

static void list_insert_head(List *list, void *elem) {
    ListNode *node = make_node(elem);
    node->next = list->head;
    list->head = node;
    if (!list->tail) list->tail = node;
    list->len++;
}

int list_len(List *list) {
  return list->len;
}

Iter *list_iter(List *list) {
  Iter *r = malloc(sizeof(Iter));
  r->ptr = list->head;
  return r;
}

void *iter_next(Iter *iter) {
  if (!iter->ptr)
    return NULL;
  void *r = iter->ptr->elem;
  iter->ptr = iter->ptr->next;
  return r;
}

bool iter_end(Iter *iter) {
  return !iter->ptr;
}

List *list_reverse(List *list) {
  List *r = make_list();
  for (Iter *i = list_iter(list); !iter_end(i);) {
    list_insert_head(r, iter_next(i));
  }
  return r;
}
