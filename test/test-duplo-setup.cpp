#include "test-duplo.h"

TEST_F(TestDuplo, Setup) {
  mr_init_threading();

  std::future<void> ret_const = std::async(std::launch::async, [this]() {
    duplo_const.Setup();
  });

  std::future<void> ret_eval = std::async(std::launch::async, [this]() {
    duplo_eval.Setup();
  });

  ret_const.wait();
  ret_eval.wait();
  mr_end_threading();

  //Check initial OT extension
  for (int i = 0; i < NUM_COMMIT_SEED_OT; ++i) {
    if (GetBit(i, duplo_eval.commit_seed_choices.GetArray())) {
      ASSERT_TRUE(std::equal(duplo_eval.commit_seed_OTs[i], duplo_eval.commit_seed_OTs[i + 1], duplo_const.commit_seed_OTs1[i]));
    } else {
      ASSERT_TRUE(std::equal(duplo_eval.commit_seed_OTs[i], duplo_eval.commit_seed_OTs[i + 1], duplo_const.commit_seed_OTs0[i]));
    }
  }
}