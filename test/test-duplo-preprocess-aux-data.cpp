#include "test-duplo.h"

TEST_F(TestDuplo, PreprocessAuxData) {
  mr_init_threading();
  Circuit aes_circuit = read_text_circuit("test/data/AES-non-expanded.txt");

  std::future<void> ret_const = std::async(std::launch::async, [this, &aes_circuit]() {
    duplo_const.Setup();
    duplo_const.PreprocessComponentType("const_aes", aes_circuit, 20, num_execs_components);
  });

  std::future<void> ret_eval = std::async(std::launch::async, [this, &aes_circuit]() {
    duplo_eval.Setup();
    duplo_eval.PreprocessComponentType("eval_aes", aes_circuit, 20, num_execs_components);
  });

  ret_const.wait();
  ret_eval.wait();
  mr_end_threading();

  uint32_t num_sessions = duplo_const.circuit_info.size();

  //Check stored aux data
  for (int l = 0; l < num_sessions; ++l) {
    std::string const_session_component_type(std::get<0>(duplo_const.circuit_info[l]));
    std::string eval_session_component_type(std::get<0>(duplo_eval.circuit_info[l]));
    Circuit& session_circuit = std::get<1>(duplo_const.circuit_info[l]);
    uint64_t num_buckets = std::get<2>(duplo_const.circuit_info[l]);

    BYTEArrayVector const_curr_session_aux_info;
    duplo_const.persistent_storage.ReadBuckets(const_session_component_type, AUXDATA, 0, num_buckets, const_curr_session_aux_info);

    BYTEArrayVector eval_curr_session_aux_info;
    duplo_eval.persistent_storage.ReadBuckets(eval_session_component_type, AUXDATA, 0, num_buckets, eval_curr_session_aux_info);

    for (int i = 0; i < num_buckets; ++i) {
      //Check delta
      uint8_t* delta_share0 = ConstGarbledCircuit::delta_commit0(session_circuit, const_curr_session_aux_info[i]);
      uint8_t* delta_share1 = ConstGarbledCircuit::delta_commit1(session_circuit, const_curr_session_aux_info[i]);
      uint8_t* delta_share = EvalGarbledCircuit::delta_share(session_circuit, eval_curr_session_aux_info[i]);
      for (int j = 0; j < CODEWORD_BITS; j++) {
        if (GetBit(j, duplo_eval.commit_seed_choices.GetArray())) {
          ASSERT_EQ(GetBitReversed(j, delta_share), GetBitReversed(j, delta_share1));
        } else {
          ASSERT_EQ(GetBitReversed(j, delta_share), GetBitReversed(j, delta_share0));
        }
      }

      //Check inputs
      for (int w = 0; w < session_circuit.num_inp_wires; ++w) {
        for (int j = 0; j < CODEWORD_BITS; j++) {
          if (GetBit(j, duplo_eval.commit_seed_choices.GetArray())) {
            ASSERT_EQ(GetBitReversed(j, EvalGarbledCircuit::inp_key_share(session_circuit, eval_curr_session_aux_info[i], w)), GetBitReversed(j, ConstGarbledCircuit::inp_key_commit1(session_circuit, const_curr_session_aux_info[i], w)));
          } else {
            ASSERT_EQ(GetBitReversed(j, EvalGarbledCircuit::inp_key_share(session_circuit, eval_curr_session_aux_info[i], w)), GetBitReversed(j, ConstGarbledCircuit::inp_key_commit0(session_circuit, const_curr_session_aux_info[i], w)));
          }
        }
      }

      //Check outputs
      for (int w = 0; w < session_circuit.num_out_wires; ++w) {
        for (int j = 0; j < CODEWORD_BITS; j++) {
          if (GetBit(j, duplo_eval.commit_seed_choices.GetArray())) {
            ASSERT_EQ(GetBitReversed(j, EvalGarbledCircuit::out_key_share(session_circuit, eval_curr_session_aux_info[i], w)), GetBitReversed(j, ConstGarbledCircuit::out_key_commit1(session_circuit, const_curr_session_aux_info[i], w)));
          } else {
            ASSERT_EQ(GetBitReversed(j, EvalGarbledCircuit::out_key_share(session_circuit, eval_curr_session_aux_info[i], w)), GetBitReversed(j, ConstGarbledCircuit::out_key_commit0(session_circuit, const_curr_session_aux_info[i], w)));
          }
        }
      }
    }
  }
}