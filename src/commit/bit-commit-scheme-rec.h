#ifndef DUPLO_COMMIT_BITCOMMITSCHEME_REC_H_
#define DUPLO_COMMIT_BITCOMMITSCHEME_REC_H_

#include "commit/bit-commit-scheme.h"
#include "commit/ecc.h"

class BitCommitReceiver : public BitCommitScheme {
public:
  
  BitCommitReceiver(CommonTools& common_tools, uint8_t seeds[], uint8_t choices[]);

  //Committing
  bool Commit(uint32_t num_commits, BYTEArrayVector& commit_shares, uint32_t current_counter);

  //BatchDecommit
  bool BatchDecommit(uint8_t computed_shares[], int num_values, uint8_t values[]);

  //Verify
  bool VerifyTransposedDecommits(uint8_t decommit_shares0[], uint8_t decommit_shares1[], uint8_t computed_shares[], int num_values);

private:
  void ExpandAndTranspose(std::vector<std::unique_ptr<uint8_t[]>>& matrices, std::vector<uint8_t*>& commit_shares, uint32_t current_counter);
  void CheckbitCorrection(std::vector<uint8_t*>& commit_shares);
  bool ConsistencyCheck(std::vector<std::unique_ptr<uint8_t[]>>& matrices, std::vector<uint8_t*>& commit_shares);

  //Convenience pointers
  uint8_t* seeds;
  uint8_t* choices;

  const int transpose_matrix_values_size = col_dim_bytes;

};

static inline bool VerifyBitDecommits(uint8_t decommit_share0[], uint8_t decommit_share1[], uint8_t computed_shares[], uint8_t res_values[], uint8_t choices[], ECC* code, int num_values) {

  for (int j = 0; j < num_values; ++j) {
    //Check value shares
    for (int i = 0; i < 1; ++i) {
      if (((computed_shares + j * BIT_CODEWORD_BYTES)[i] ^
           ((decommit_share1 + j * BIT_CODEWORD_BYTES)[i] &
            REVERSE_BYTE_ORDER[choices[i]]) ^
           ((decommit_share0 + j * BIT_CODEWORD_BYTES)[i] &
            ~REVERSE_BYTE_ORDER[choices[i]])) != 0) {
        return false;
      }
    }

    //Check checkbit shares
    for (int i = 0; i < BIT_CODEWORD_BYTES; ++i) {
      if (((computed_shares + j * BIT_CODEWORD_BYTES)[i] ^
           ((decommit_share1 + j * BIT_CODEWORD_BYTES)[i] &
            REVERSE_BYTE_ORDER[choices[i]]) ^
           ((decommit_share0 + j * BIT_CODEWORD_BYTES)[i] &
            ~REVERSE_BYTE_ORDER[choices[i]])) != 0) {
        return false;
      }
    }
    XORBit(j, GetBit(0, decommit_share0 + j * BIT_CODEWORD_BYTES) ^ GetBit(0, decommit_share1 + j * BIT_CODEWORD_BYTES), res_values);
  }

  return true; //All checks passed!
};

#endif /* DUPLO_COMMIT_BITCOMMITSCHEME_REC_H_ */