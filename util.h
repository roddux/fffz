// stolen from https://github.com/neovim/neovim/blob/master/src/nvim/log.h
#define LOG(fmt, ...)                                                      \
    do {                                                                   \
        fprintf(stderr, "%s/%s():%d - " fmt, __FILE__, __func__, __LINE__, \
                ##__VA_ARGS__);                                            \
    } while (0)

#define CHECK(COND, MSG) \
    if (COND) {          \
        LOG(MSG);        \
        perror(0);       \
        exit(-1);        \
    }
