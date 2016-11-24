#include "dot/alsz-dot-ext.h"

ALSZDOTExt::ALSZDOTExt(CommonTools& common_tools) :
  common_tools(common_tools),
  net(common_tools.ip_address.c_str(), common_tools.port, common_tools.net_role),
  bit_length_outer(CSEC),
  num_seed_OT(bit_length_outer + 2 * SSEC),
  bit_length_inner(num_seed_OT),
  num_check_OT(2 * num_seed_OT + SSEC),
  num_priv_amp_threads(std::thread::hardware_concurrency()),
  num_OT_threads(1),
  s_type(Snd_GC_OT),
  r_type(Rec_OT),
  m_eFType(ECC_FIELD),
  num_snd_vals(2),
  m_bUseMinEntCorAssumption(false),
  m_fMaskFct(std::make_unique<XORMasking>(bit_length_inner)) {

  if (common_tools.net_role) { //Client
    thread t([this]() { net.ConnectAndStart();});
    t.detach();

  } else { //Server
    thread t([this]() { net.ListenAndStart();});
    t.detach();
  }
}

void ALSZDOTExt::PrivacyAmplification(uint8_t priv_amp_matrix[], int rows_bytes, int columns_bits, int num_vecs, uint8_t base_inner[], uint8_t base_outer[]) {
  std::vector<int> vecs_from, vecs_to;
  std::vector<std::future<void>> execs;
  PartitionBufferFixedNum(vecs_from, vecs_to, num_priv_amp_threads, num_vecs);

  //Run the naive privacy amplification using common_tools.num_cpus executions. The below method is straightforward and could probably be optimized using specific binary matrix multiplication libraries. However overall the work is not that significant as we do not need that many Delta-OTs. If needed find a more efficient way of doing this.
  for (int i = 0; i < num_priv_amp_threads; ++i) {
    int from = vecs_from[i];
    int to = vecs_to[i];
    execs.emplace_back(std::async(std::launch::async, [from, to, columns_bits, base_inner, base_outer, rows_bytes, priv_amp_matrix]() {
      for (int vec = from; vec < to; ++vec) { //For each entry of vectors
        for (int bit = 0; bit < columns_bits; ++bit) {
          if (GetBitReversed(vec * columns_bits + bit, base_inner)) {
            XOR_128(base_outer + vec * rows_bytes, priv_amp_matrix + (bit * rows_bytes));
          }
        }
      }
    }));
  }

  for (std::future<void>& res : execs) {
    res.wait();
  }
}

void ALSZDOTExt::GeneratePrivAmpMatrix(uint8_t priv_amp_seed[], uint8_t priv_amp_matrix[], int size) {
  PRNG rnd;
  rnd.SetSeed(priv_amp_seed);
  rnd.GenRnd(priv_amp_matrix, size);
}