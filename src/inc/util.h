#define DEBUG 0
#include <stdio.h>   // fprintf
#include <stdlib.h>  // exit
#define LOG(...)                                                               \
    if (DEBUG) {                                                               \
        do {                                                                   \
            fprintf(stderr, "%s/%s():%d - ", __SRCFILE__, __func__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                                      \
        } while (0);                                                           \
    }

#define CHECKP(COND) \
    if (COND) {      \
        LOG(#COND);  \
        perror(0);   \
        exit(-1);    \
    }

#define CHECK(COND, MSG) \
    if (COND) {          \
        LOG(MSG);        \
        perror(0);       \
        exit(-1);        \
    }
