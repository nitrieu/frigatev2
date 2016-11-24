#include "test.h"

#include "commit/commit-scheme-snd.h"
#include "commit/commit-scheme-rec.h"
#include "commit/bit-commit-scheme-snd.h"
#include "commit/bit-commit-scheme-rec.h"

class CommitTest : public ::testing::Test {

protected:
  zmq::context_t context_snd;
  zmq::context_t context_rec;

  uint32_t current_counter = 0;
  uint32_t num_commits = 5000;
  uint32_t num_commits_second = 10000;

  BYTEArrayVector seeds0;
  BYTEArrayVector seeds1;
  BYTEArrayVector choices;

  BYTEArrayVector commit_shares0;
  BYTEArrayVector commit_shares1;
  BYTEArrayVector commit_shares;

  BYTEArrayVector commit_shares0_second;
  BYTEArrayVector commit_shares1_second;
  BYTEArrayVector commit_shares_second;

  CommitTest() :
    context_snd(zmq::context_t(1)),
    context_rec(zmq::context_t(1)),
    seeds0(CODEWORD_BITS, CSEC_BYTES),
    seeds1(CODEWORD_BITS, CSEC_BYTES),
    choices(CODEWORD_BYTES, 1),
    commit_shares0(num_commits, CODEWORD_BYTES),
    commit_shares1(num_commits, CODEWORD_BYTES),
    commit_shares(num_commits, CODEWORD_BYTES),
    commit_shares0_second(num_commits_second, CODEWORD_BYTES),
    commit_shares1_second(num_commits_second, CODEWORD_BYTES),
    commit_shares_second(num_commits_second, CODEWORD_BYTES) {

    PRNG rnd;
    rnd.SetSeed(constant_seeds[0]);
    rnd.GenRnd(seeds0.GetArray(), seeds0.size);
    rnd.GenRnd(seeds1.GetArray(), seeds1.size);
  };
};

TEST_F(CommitTest, Share0) {

  mr_init_threading();
  CommonTools common_tools_snd(constant_seeds[0], "localhost", default_port, 0, context_snd);
  CommonTools common_tools_rec(constant_seeds[1], "localhost", default_port, 1, context_rec);
  CommitSender commit_snd(common_tools_snd, seeds0.GetArray(), seeds1.GetArray());
  CommitReceiver commit_rec(common_tools_rec, seeds0.GetArray(), choices.GetArray());

  std::future<void> ret_snd = std::async(std::launch::async, [this, &commit_snd]() {

    commit_snd.Commit(num_commits, commit_shares0, commit_shares1, current_counter);
    commit_snd.Commit(num_commits_second, commit_shares0_second, commit_shares1_second, current_counter);
  });

  std::future<void> ret_rec = std::async(std::launch::async, [this, &commit_rec]() {

    ASSERT_TRUE(commit_rec.Commit(num_commits, commit_shares, current_counter));
    ASSERT_TRUE(commit_rec.Commit(num_commits_second, commit_shares_second, current_counter));
  });

  ret_snd.wait();
  ret_rec.wait();
  mr_end_threading();

  for (int l = 0; l < num_commits; l++) {
    for (int j = 0; j < CODEWORD_BITS; j++) {
      ASSERT_EQ(GetBitReversed(j, commit_shares[l]), GetBitReversed(j, commit_shares0[l]));
    }
  }

  for (int l = 0; l < num_commits_second; l++) {
    for (int j = 0; j < CODEWORD_BITS; j++) {
      ASSERT_EQ(GetBitReversed(j, commit_shares_second[l]), GetBitReversed(j, commit_shares0_second[l]));
    }
  }
}

TEST_F(CommitTest, Share1) {
  std::fill(choices.GetArray(), choices.GetArray() + CODEWORD_BYTES, 0xFF);

  mr_init_threading();
  CommonTools common_tools_snd(constant_seeds[0], "localhost", default_port, 0, context_snd);
  CommonTools common_tools_rec(constant_seeds[1], "localhost", default_port, 1, context_rec);

  CommitSender commit_snd(common_tools_snd, seeds0.GetArray(), seeds1.GetArray());
  CommitReceiver commit_rec(common_tools_rec, seeds1.GetArray(), choices.GetArray());

  std::future<void> ret_snd = std::async(std::launch::async, [this, &commit_snd]() {

    commit_snd.Commit(num_commits, commit_shares0, commit_shares1, current_counter);
    commit_snd.Commit(num_commits_second, commit_shares0_second, commit_shares1_second, current_counter);
  });

  std::future<void> ret_rec = std::async(std::launch::async, [this, &commit_rec]() {

    ASSERT_TRUE(commit_rec.Commit(num_commits, commit_shares, current_counter));
    ASSERT_TRUE(commit_rec.Commit(num_commits_second, commit_shares_second, current_counter));
  });


  ret_snd.wait();
  ret_rec.wait();
  mr_end_threading();

  for (int l = 0; l < num_commits; l++) {
    for (int j = 0; j < CODEWORD_BITS; j++) {
      ASSERT_EQ(GetBitReversed(j, commit_shares[l]), GetBitReversed(j, commit_shares1[l]));
    }
  }

  for (int l = 0; l < num_commits_second; l++) {
    for (int j = 0; j < CODEWORD_BITS; j++) {
      ASSERT_EQ(GetBitReversed(j, commit_shares_second[l]), GetBitReversed(j, commit_shares1_second[l]));
    }
  }
}

class BitCommitTest : public ::testing::Test {

protected:
  zmq::context_t context_snd;
  zmq::context_t context_rec;

  BYTEArrayVector seeds0;
  BYTEArrayVector seeds1;
  BYTEArrayVector choices;

  uint32_t current_counter = 0;
  uint32_t num_commits = 5000;
  uint32_t num_commits_second = 10000;
  BYTEArrayVector commit_shares0;
  BYTEArrayVector commit_shares1;
  BYTEArrayVector commit_shares;

  BitCommitTest() :
    context_snd(zmq::context_t(1)),
    context_rec(zmq::context_t(1)),
    seeds0(CODEWORD_BITS, CSEC_BYTES),
    seeds1(CODEWORD_BITS, CSEC_BYTES),
    choices(CODEWORD_BYTES, 1),
    commit_shares0(num_commits, BIT_CODEWORD_BYTES),
    commit_shares1(num_commits, BIT_CODEWORD_BYTES),
    commit_shares(num_commits, BIT_CODEWORD_BYTES) {

    PRNG rnd;
    rnd.SetSeed(constant_seeds[0]);
    rnd.GenRnd(seeds0.GetArray(), seeds0.size);
    rnd.GenRnd(seeds1.GetArray(), seeds1.size);
  };
};

TEST_F(BitCommitTest, Share0) {

  mr_init_threading();
  CommonTools common_tools_snd(constant_seeds[0], "localhost", default_port, 0, context_snd);
  CommonTools common_tools_rec(constant_seeds[1], "localhost", default_port, 1, context_rec);
  BitCommitSender commit_snd(common_tools_snd, seeds0.GetArray(), seeds1.GetArray());
  BitCommitReceiver commit_rec(common_tools_rec, seeds0.GetArray(), choices.GetArray());

  std::future<void> ret_snd = std::async(std::launch::async, [this, &commit_snd]() {

    commit_snd.Commit(num_commits, commit_shares0, commit_shares1, current_counter);

    BYTEArrayVector tmp(BITS_TO_BYTES(num_commits), 1);
    for (int i = 0; i < num_commits; ++i) {
      SetBit(i, GetBit(0, commit_shares0[i]), tmp.GetArray());
      XORBit(i, GetBit(0, commit_shares1[i]), tmp.GetArray());
    }
    commit_snd.common_tools.chan.Send(tmp.GetArray(), tmp.size);  
    commit_snd.BatchDecommit(commit_shares0.GetArray(), commit_shares1.GetArray(), num_commits);
    
  });

  std::future<void> ret_rec = std::async(std::launch::async, [this, &commit_rec]() {

    ASSERT_TRUE(commit_rec.Commit(num_commits, commit_shares, current_counter));

    BYTEArrayVector tmp(BITS_TO_BYTES(num_commits), 1);
    commit_rec.common_tools.chan.ReceiveBlocking(tmp.GetArray(), tmp.size);
    ASSERT_TRUE(commit_rec.BatchDecommit(commit_shares.GetArray(), num_commits, tmp.GetArray()));
  });

  ret_snd.wait();
  ret_rec.wait();
  mr_end_threading();

  for (int l = 0; l < num_commits; l++) {
    for (int j = 0; j < BIT_CODEWORD_BITS; j++) {
      ASSERT_EQ(GetBitReversed(j, commit_shares[l]), GetBitReversed(j, commit_shares0[l]));
    }
  }
}

TEST_F(BitCommitTest, Share1) {
  std::fill(choices.GetArray(), choices.GetArray() + BIT_CODEWORD_BYTES, 0xFF);

  mr_init_threading();
  CommonTools common_tools_snd(constant_seeds[0], "localhost", default_port, 0, context_snd);
  CommonTools common_tools_rec(constant_seeds[1], "localhost", default_port, 1, context_rec);
  BitCommitSender commit_snd(common_tools_snd, seeds0.GetArray(), seeds1.GetArray());
  BitCommitReceiver commit_rec(common_tools_rec, seeds1.GetArray(), choices.GetArray());

  std::future<void> ret_snd = std::async(std::launch::async, [this, &commit_snd]() {

    commit_snd.Commit(num_commits, commit_shares0, commit_shares1, current_counter);

    BYTEArrayVector tmp(BITS_TO_BYTES(num_commits), 1);
    for (int i = 0; i < num_commits; ++i) {
      SetBit(i, GetBit(0, commit_shares0[i]), tmp.GetArray());
      XORBit(i, GetBit(0, commit_shares1[i]), tmp.GetArray());
    }
    commit_snd.common_tools.chan.Send(tmp.GetArray(), tmp.size);  
    commit_snd.BatchDecommit(commit_shares0.GetArray(), commit_shares1.GetArray(), num_commits);
  });

  std::future<void> ret_rec = std::async(std::launch::async, [this, &commit_rec]() {

    ASSERT_TRUE(commit_rec.Commit(num_commits, commit_shares, current_counter));

    BYTEArrayVector tmp(BITS_TO_BYTES(num_commits), 1);
    commit_rec.common_tools.chan.ReceiveBlocking(tmp.GetArray(), tmp.size);
    ASSERT_TRUE(commit_rec.BatchDecommit(commit_shares.GetArray(), num_commits, tmp.GetArray()));
  });


  ret_snd.wait();
  ret_rec.wait();
  mr_end_threading();

  for (int l = 0; l < num_commits; l++) {
    for (int j = 0; j < BIT_CODEWORD_BITS; j++) {
      ASSERT_EQ(GetBitReversed(j, commit_shares[l]), GetBitReversed(j, commit_shares1[l]));
    }
  }
}