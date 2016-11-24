#include "util/sha1.h"

void sha1_compress(uint32_t state[5], const uint8_t block[64]) {
    printf("%s\n", "here!");
    sha1_update_intel((int*)state, (const char*)block);
    printf("%s\n", "done!");
}