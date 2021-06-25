#include <assert.h>
#include <inttypes.h>

// Assumptions I make a lot because I mainly use x86_64
static_assert(sizeof(uint64_t) == sizeof(unsigned long) &&
                  sizeof(uint64_t) == 8,
              "Expected uint64_t to be unsigned long == 8*8(64)");

static_assert(sizeof(int64_t) == sizeof(signed long) && sizeof(int64_t) == 8,
              "Expected int64_t to be signed long == 8*8(64)");

static_assert(sizeof(uint32_t) == sizeof(unsigned int) && sizeof(uint32_t) == 4,
              "Expected uint32_t to be unsigned int == 8*4(32)");

static_assert(sizeof(int32_t) == sizeof(signed int) && sizeof(int32_t) == 4,
              "Expected int32_t to be signed int == 8*4(32)");

static_assert(sizeof(uint8_t) == sizeof(unsigned char) && sizeof(uint8_t) == 1,
              "Expected uint8_t to be unsigned char == 8*1(8)");

static_assert(sizeof(int8_t) == sizeof(signed char) && sizeof(int8_t) == 1,
              "Expected int8_t to be signed char == 8*1(8)");

uint8_t *x;
unsigned char *y;
static_assert(sizeof(x) == sizeof(y) && sizeof(x) == 8,
              "Expected *uint8_t to be *unsigned char == 8*8(64)");

static_assert(sizeof(uintptr_t) == sizeof(x) && sizeof(uintptr_t) == 8,
              "Expected uintptr_t to be *uint8_t == 8*8(64)");
