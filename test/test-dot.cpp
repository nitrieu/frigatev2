#include "test.h"

#include "dot/alsz-dot-ext-snd.h"
#include "dot/alsz-dot-ext-rec.h"
#include "util/byte-array-vec.h"

class DOTTest : public ::testing::Test {

protected:
  zmq::context_t context_snd;
  zmq::context_t context_rec;

  uint32_t num_ots = 5000;
  uint32_t num_otss_second = 10000;

  BYTEArrayVector dot_base;
  BYTEArrayVector dot_delta;
  
  BYTEArrayVector dot_response;
  BYTEArrayVector dot_choices;

  DOTTest() :
    context_snd(zmq::context_t(1)),
    context_rec(zmq::context_t(1)),
    dot_base(num_ots, CSEC_BYTES),
    dot_delta(1, CSEC_BYTES),
    dot_response(num_ots, CSEC_BYTES),
    dot_choices(BITS_TO_BYTES(num_ots), 1) {
    
  };
};

TEST_F(DOTTest, DOTCorrect) {

  mr_init_threading();
  CommonTools common_tools_snd(constant_seeds[0], "localhost", default_port, 0, context_snd);
  CommonTools common_tools_rec(constant_seeds[1], "localhost", default_port, 1, context_rec);
  ALSZDOTExtSnd dot_snd(common_tools_snd, 1);
  ALSZDOTExtRec dot_rec(common_tools_rec);

  std::future<void> ret_snd = std::async(std::launch::async, [this, &dot_snd]() {
    dot_snd.InitOTSender();
    dot_snd.Send(num_ots, dot_base.GetArray(), dot_delta.GetArray());
  });

  std::future<void> ret_rec = std::async(std::launch::async, [this, &dot_rec]() {
    dot_rec.InitOTReceiver();
    dot_rec.Receive(num_ots, dot_response.GetArray(), dot_choices.GetArray());
  });

  ret_snd.wait();
  ret_rec.wait();
  mr_end_threading();

  uint8_t tmp[CSEC_BYTES] = {0};
  for (int i = 0; i < num_ots; i++) {
    if (GetBit(i, dot_choices.GetArray())) {
      XOR_128(tmp, dot_base[i], dot_delta.GetArray());
      
      for (int j = 0; j < CSEC_BYTES; j++) {
        ASSERT_EQ(tmp[j], dot_response[i][j]);
      }
      
      memset(tmp, 0, CSEC_BYTES);
    } else {
      
      for (int j = 0; j < CSEC_BYTES; j++) {
        ASSERT_EQ(dot_base[i][j], dot_response[i][j]);
      }
    }
  }
}