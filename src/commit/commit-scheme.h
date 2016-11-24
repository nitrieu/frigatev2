#ifndef DUPLO_COMMIT_COMMITSCHEME_H_
#define DUPLO_COMMIT_COMMITSCHEME_H_

#include "util/common-tools.h"
#include "commit/ecc.h"
#include "util/byte-array-vec.h"


class CommitScheme {
public:
  CommitScheme(CommonTools& common_tools);

  CommonTools& common_tools;

  std::unique_ptr<ECC> code;

  static const int row_dim = PAD_TO_MULTIPLE(CODEWORD_BITS, 64); //Makes row_dim 320 which is needed for our matrix transposition code.
  static const int row_dim_bytes = BITS_TO_BYTES(row_dim);
  static const int col_blocks = 8; //Chosen for efficiency. This gave the best result.
  static const int col_dim_single = AES_BITS; //We process AES_BITS columns at a time with our PCLMULQDQ code.
  static const int col_dim_single_bytes = BITS_TO_BYTES(col_dim_single);
  static const int col_dim = col_blocks * col_dim_single;
  static const int col_dim_bytes = BITS_TO_BYTES(col_dim);

  static const int transpose_matrix_size = BITS_TO_BYTES(row_dim * col_dim);

  int num_commits_produced;
  int num_blocks;
};

static uint32_t GetIncreasedCounter(uint32_t current_counter, uint32_t num_commits) {
  //First we increment the seeds to the current block.
  int increase_counter_pr_block = CEIL_DIVIDE(CommitScheme::col_dim_bytes, AES_BYTES * PIPELINES);
  int num_blocks = CEIL_DIVIDE(num_commits + AES_BITS, CommitScheme::col_dim);
  
  return (current_counter + increase_counter_pr_block * num_blocks);
};

#endif /* DUPLO_COMMIT_COMMITSCHEME_H_ */