// stolen from https://github.com/neovim/neovim/blob/master/src/nvim/log.h
#define DEBUG 1
#include <stdio.h>   // fprintf
#include <stdlib.h>  // exit
#define LOG(...)                                                               \
    if (DEBUG) {                                                               \
        do {                                                                   \
            fprintf(stderr, "%s/%s():%d - ", __SRCFILE__, __func__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                                      \
        } while (0);                                                           \
    }

// fprintf(stderr, "%s/%s():%d - ", __FILE__, __func__, __LINE__);

#define CHECK(COND, MSG) \
    if (COND) {          \
        LOG(MSG);        \
        perror(0);       \
        exit(-1);        \
    }
