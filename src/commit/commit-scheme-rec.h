#ifndef DUPLO_COMMIT_COMMITSCHEME_REC_H_
#define DUPLO_COMMIT_COMMITSCHEME_REC_H_

#include "commit/commit-scheme.h"

class CommitReceiver : public CommitScheme {
public:

  CommitReceiver(CommonTools& common_tools, uint8_t seeds[], uint8_t choices[]);

  //Committing
  bool Commit(uint32_t num_commits, BYTEArrayVector& commit_shares, uint32_t current_counter, uint32_t set_lsb_start_idx = 0);

  //Chosen Commit/Decommit.
  // void ChosenCommit(int num_values);
  // bool ChosenDecommit(uint8_t computed_shares[], uint8_t decommit_values_res[], std::vector<uint64_t> idxs, int num_values);

  //BatchDecommit
  bool BatchDecommit(uint8_t computed_shares[], int num_values, uint8_t values[]);

  //Verify
  bool VerifyTransposedDecommits(uint8_t decommit_shares0[], uint8_t decommit_shares1[], uint8_t computed_shares[], int num_values);

private:
  void ExpandAndTranspose(std::vector<std::unique_ptr<uint8_t[]>>& matrices, std::vector<uint8_t*>& commit_shares, uint32_t current_counter);
  void CheckbitCorrection(std::vector<uint8_t*>& commit_shares, uint32_t set_lsb_start_idx, uint32_t num_commits);
  bool ConsistencyCheck(std::vector<std::unique_ptr<uint8_t[]>>& matrices, std::vector<uint8_t*>& commit_shares);

  //Convenience pointers
  uint8_t* seeds;
  uint8_t* choices;

  //Chosen commits data
  // int num_chosen_commits;
  // std::unique_ptr<uint8_t[]> chosen_commit_values;

  //Size of the matrices used for transposing the postulated opening values
  const int row_dim_values = AES_BITS;
  const int row_dim_values_bytes = AES_BYTES;
  const int transpose_matrix_values_size = row_dim_values_bytes * col_dim;

};

static inline bool VerifyDecommits(uint8_t decommit_share0[], uint8_t decommit_share1[], uint8_t computed_shares[], uint8_t res_values[], uint8_t choices[], ECC* code, int num_values) {

  uint8_t c[BCH_BYTES] = {0};
  uint8_t c1[BCH_BYTES];

  for (int j = 0; j < num_values; ++j) {
    //Check value shares
    for (int i = 0; i < CSEC_BYTES; ++i) {
      if (((computed_shares + j * CODEWORD_BYTES)[i] ^
           ((decommit_share1 + j * CODEWORD_BYTES)[i] &
            REVERSE_BYTE_ORDER[choices[i]]) ^
           ((decommit_share0 + j * CODEWORD_BYTES)[i] &
            ~REVERSE_BYTE_ORDER[choices[i]])) != 0) {
        return false;
      }
    }

    //Check checkbit shares
    for (int i = 0; i < BCH_BYTES; ++i) {
      if (((computed_shares + j * CODEWORD_BYTES)[CSEC_BYTES + i] ^
           ((decommit_share1 + j * CODEWORD_BYTES)[CSEC_BYTES + i] &
            REVERSE_BYTE_ORDER[choices[CSEC_BYTES + i]]) ^
           ((decommit_share0 + j * CODEWORD_BYTES)[CSEC_BYTES + i] &
            ~REVERSE_BYTE_ORDER[choices[CSEC_BYTES + i]])) != 0) {
        return false;
      }
    }
    XOR_128(res_values + j * CSEC_BYTES, decommit_share0 + j * CODEWORD_BYTES, decommit_share1 + j * CODEWORD_BYTES);
  }

  return true; //All checks passed!
};

#endif /* DUPLO_COMMIT_COMMITSCHEME_REC_H_ */