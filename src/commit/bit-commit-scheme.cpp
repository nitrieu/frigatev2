#include "commit/bit-commit-scheme.h"

BitCommitScheme::BitCommitScheme(CommonTools& common_tools) :
  common_tools(common_tools) { }

void BitCommitScheme::Encode(uint8_t bit, uint8_t array[]) {
  std::fill(array, array + BIT_CODEWORD_BYTES, bit_to_byte[bit]);
}