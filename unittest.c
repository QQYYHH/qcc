/*
 * @Author: QQYYHH
 * @Date: 2022-04-26 16:06:04
 * @LastEditTime: 2022-04-26 16:14:48
 * @LastEditors: QQYYHH
 * @Description: 单元测试
 * @FilePath: /pwn/qcc/unittest.c
 * welcome to my github: https://github.com/QQYYHH
 */

#include <stdio.h>
#include <string.h>
#include "qcc.h"

void assert_equal(char *s, char *t)
{
    if (strcmp(s, t))
        error("Expected %s but got %s", s, t);
}

void test_string()
{
    String *s = make_string();
    string_append(s, 'a');
    assert_equal("a", get_cstring(s));
    string_append(s, 'b');
    assert_equal("ab", get_cstring(s));

    string_appendf(s, ".");
    assert_equal("ab.", get_cstring(s));
    string_appendf(s, "%s", "0123456789");
    assert_equal("ab.0123456789", get_cstring(s));
}

int main(int argc, char **argv)
{
    test_string();
    printf("Unittest Passed\n");
    return 0;
}