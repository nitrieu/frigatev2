#include "test.h"

#include "util/common-tools.h"
extern "C" {
#include "util/sha1.h"
}

TEST(Timings, Sha1) {
  zmq::context_t context(1);
  CommonTools common_tools(constant_seeds[0], "localhost", default_port, 0, context, GLOBAL_PARAMS_CHAN);

  std::vector<uint8_t> dummy(10000);

  uint8_t h_0[20];
  uint8_t h_1[20];
  uint32_t iters = 1000;
  
  auto old_start = GET_TIME();
  for (int i = 0; i < iters; ++i) {
    common_tools.crypt.hash(h_0, 20, dummy.data(), dummy.size() * 8);
  }
  auto old_end = GET_TIME();
  PrintTimePerBucket(old_start, old_end, iters, "old time");

  auto new_start = GET_TIME();
  for (int i = 0; i < iters; ++i) {
    sha1_hash_c(dummy.data(), dummy.size() * 8, (uint32_t*) h_1);
  }
  auto new_end = GET_TIME();
  PrintTimePerBucket(new_start, new_end, iters, "new time");

}