#ifndef DUPLO_COMMIT_COMMITSCHEME_SND_H_
#define DUPLO_COMMIT_COMMITSCHEME_SND_H_

#include "commit/commit-scheme.h"

class CommitSender : public CommitScheme {
public:
  
  CommitSender(CommonTools& common_tools, uint8_t seeds0[], uint8_t seeds1[]);

  void Commit(uint32_t num_commits, BYTEArrayVector& commit_shares0, BYTEArrayVector& commit_shares1, uint32_t current_counter, uint32_t set_lsb_start_idx = 0);
  // void ChosenCommit(uint8_t values[], std::vector<uint64_t> idxs, int num_values);
  void BatchDecommit(uint8_t decommit_shares0[], uint8_t decommit_shares1[], int num_values);
    
  //Convenience pointers
  uint8_t* seeds0;
  uint8_t* seeds1;
  

private:
  void ExpandAndTranspose(std::vector<std::unique_ptr<uint8_t[]>>& matrices0, std::vector<std::unique_ptr<uint8_t[]>>& matrices1, std::vector<uint8_t*>& commit_shares0, std::vector<uint8_t*>& commit_shares1, uint32_t current_counter);
  void CheckbitCorrection(std::vector<uint8_t*>& commit_shares0, std::vector<uint8_t*>& commit_shares1, uint32_t set_lsb_start_idx, uint32_t num_commits);
  void ConsistencyCheck(std::vector<std::unique_ptr<uint8_t[]>>& matrices0, std::vector<std::unique_ptr<uint8_t[]>>& matrices1, std::vector<uint8_t*>& commit_shares0, std::vector<uint8_t*>& commit_shares1);
};
#endif /* DUPLO_COMMIT_COMMITSCHEME_SND_H_ */