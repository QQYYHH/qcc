/*
 * @Author: QQYYHH
 * @Date: 2022-06-01 18:09:16
 * @LastEditTime: 2022-06-01 19:45:27
 * @LastEditors: QQYYHH
 * @Description: list structure
 * @FilePath: /pwn/qcc/list.h
 * welcome to my github: https://github.com/QQYYHH
 */
#include <stdbool.h>

typedef struct ListNode{
    void *elem;
    struct ListNode *next;
}ListNode;

typedef struct List{
    int len;
    ListNode *head, *tail;
}List;

// List Iterator
typedef struct Iter{
    ListNode *ptr;
}Iter;

List *make_list(void);
void list_append(List *list, void *elem);
List *list_reverse(List *list);
int list_len(List *list);
Iter *list_iter(List *list);
void *iter_next(Iter *iter);
bool iter_end(Iter *iter);

#define EMPTY_LIST                                      \
    (&(List){ .len = 0, .head = NULL, .tail = NULL })

