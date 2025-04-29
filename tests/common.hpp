#pragma once

#include <string>

#include <stdio.h>
#include <stdlib.h>

#define MUST_LIBC(x) ( assert_libc_success((x), std::string(__FILE__) + ":" + std::to_string(__LINE__) + ": " + #x) )
#define MUST_LIBC_NOT_NULL(x) ( assert_libc_success_not_null((x), std::string(__FILE__) + ":" + std::to_string(__LINE__) + ": " + #x) )
#define MUST(x) do { if (!(x)) { fprintf(stderr, "%s:%d: Failed assertion: %s\n", __FILE__, __LINE__, #x); exit(1); } } while(0)

template <typename T>
static inline T assert_libc_success(T return_value, std::string stringified_expression) {
    if (return_value == -1) {
        perror(stringified_expression.c_str());
        exit(1);
    }
    return return_value;
}


template <typename T>
static inline T assert_libc_success_not_null(T return_value, std::string stringified_expression) {
    if (return_value == NULL) {
        perror(stringified_expression.c_str());
        exit(1);
    }
    return return_value;
}
