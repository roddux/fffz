/*
mOPT paper: https://www.usenix.org/system/files/sec19-lyu.pdf
"For most programs, the operators bitflip 1/1, bitflip 2/1 and arith 8/8 could
yield more interesting test cases than other operators."

lcamtuf blog:
https://lcamtuf.blogspot.com/2014/08/binary-fuzzing-strategies-what-works.html
*/

#define __SRCFILE__ "mutator"
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "util.h"

void print_bits(uint8_t *buf, uint64_t num_bits) {
    for (uint64_t c = 0; c < num_bits; c += 8) {
        for (int i = 7; 0 <= i; i--) {
            printf("%c", (buf[c] & (1 << i)) ? '1' : '0');
        }
    }
    puts("");
}

void bitflip(uint8_t *buf, uint64_t size) {
#if DEBUG_MUTATIONS
    LOG("a single bitflip!\n");
#endif
    uint64_t offset = (rand() * 1024) % size;
    uint8_t flip = 0;
    flip = 1 << (rand() % 7);
    buf[offset] = buf[offset] ^ flip;
}

void byteflip(uint8_t *buf, uint64_t size) {
#if DEBUG_MUTATIONS
    LOG("a single byteflip!\n");
#endif
    uint64_t offset = (rand() * 1024) % size;
    buf[offset] = ~buf[offset];
}

void arith(uint8_t *buf, uint64_t size) {
#if DEBUG_MUTATIONS
    LOG("a single arithmetic!\n");
#endif
    uint64_t offset = (rand() * 1024) % size;
    // "[..] -35 to +35. Past these bounds, yields drop dramatically [..]"
    int8_t adjust = rand() % 36;
    if (rand() % 2 == 0) adjust = -adjust;

    switch (rand() % 4) {
        case 0:
            *(uint8_t *)((uint8_t *)buf + offset) += adjust;
            break;
        case 1:
            *(uint16_t *)((uint8_t *)buf + offset) += adjust;
            break;
        case 2:
            *(uint32_t *)((uint8_t *)buf + offset) += adjust;
            break;
        case 3:
            *(uint64_t *)((uint8_t *)buf + offset) += adjust;
            break;
    }
}

#define MUTATOR_FN_COUNT 3
void (*mutators[])(uint8_t *, uint64_t) = {
    bitflip,
    byteflip,
    arith,
};

void do_mutate(uint8_t *buf, uint64_t size, uint8_t num_rounds) {
    uint8_t mutator_idx;
    void (*mutator)(uint8_t *, uint64_t);
    for (uint8_t round = 0; round < num_rounds; round++) {
        mutator_idx = rand() % MUTATOR_FN_COUNT;
        mutator = mutators[mutator_idx];
        mutator(buf, size);
    }
}

// allow for specifying number of rounds as last arg
void mutate(uint8_t *buf, uint64_t size, ...) {
    va_list list;
    uint8_t num_rounds;
    va_start(list, size);
    num_rounds = (uint8_t)va_arg(list, int);
    va_end(list);
    if (num_rounds == 0) num_rounds++;

#if DEBUG_MUTATIONS
    LOG("mutating buffer at addr %p of size %" PRIu64 " for %d round%s\n", buf,
        size, num_rounds, num_rounds > 1 ? "s" : "");
#endif
    do_mutate(buf, size, num_rounds);
}
