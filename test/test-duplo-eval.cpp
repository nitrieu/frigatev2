#include "test-duplo.h"

TEST_F(TestDuplo, Evaluation) {
  mr_init_threading();
  Circuit circuit = read_text_circuit("test/data/AES-non-expanded.txt");

  std::string const_circuit("const_aes");
  std::string eval_circuit("eval_aes");

  uint32_t num_iters = 50;

  std::vector<BYTEArrayVector> const_output_keys(num_iters);
  std::future<void> ret_const = std::async(std::launch::async, [this, &circuit, &const_output_keys, &const_circuit, num_iters]() {
    duplo_const.Setup();
    duplo_const.PreprocessComponentType(const_circuit, circuit, num_iters, num_execs_components);

    std::vector<std::pair<std::string, uint32_t>> local_pairs;
    std::vector<std::vector<uint8_t>> inputs;
    for (int i = 0; i < num_iters; ++i) {
      local_pairs.emplace_back(std::make_pair(const_circuit, i));
      inputs.emplace_back(std::vector<uint8_t>(BITS_TO_BYTES(circuit.num_const_inp_wires)));
    }

    duplo_const.PrepareComponents(local_pairs, num_execs_auths);

    duplo_const.EvalComponents(local_pairs, inputs, const_output_keys, num_execs_online);
  });

  std::vector<BYTEArrayVector> eval_output_keys(num_iters);
  std::vector<std::pair<std::string, uint32_t>> global_pairs;
  std::future<void> ret_eval = std::async(std::launch::async, [this, &circuit, &eval_output_keys, &global_pairs, &eval_circuit, num_iters]() {
    duplo_eval.Setup();
    duplo_eval.PreprocessComponentType(eval_circuit, circuit, num_iters, num_execs_components);

    std::vector<std::vector<uint8_t>> inputs;
    for (int i = 0; i < num_iters; ++i) {
      global_pairs.emplace_back(std::make_pair(eval_circuit, i));
      inputs.emplace_back(std::vector<uint8_t>(BITS_TO_BYTES(circuit.num_eval_inp_wires)));
    }

    duplo_eval.PrepareComponents(global_pairs, num_execs_auths);

    duplo_eval.EvalComponents(global_pairs, inputs, eval_output_keys, num_execs_online);
  });

  ret_const.wait();
  ret_eval.wait();
  mr_end_threading();
  uint32_t num_circuits_tested = num_iters;

  for (int i = 0; i < num_circuits_tested; ++i) {
    std::string const_session_component_type(const_circuit);
    uint32_t current_aes_idx = std::get<1>(global_pairs[i]);

    BYTEArrayVector const_curr_session_aux_info;
    duplo_const.persistent_storage.ReadBuckets(const_session_component_type, AUXDATA, current_aes_idx, 1, const_curr_session_aux_info);

    BYTEArrayVector head_inp_perm_bits_debug(BITS_TO_BYTES(circuit.num_inp_wires), 1);

    //Check delta
    uint8_t* delta_share0 = ConstGarbledCircuit::delta_commit0(circuit, const_curr_session_aux_info.GetArray());
    uint8_t* delta_share1 = ConstGarbledCircuit::delta_commit1(circuit, const_curr_session_aux_info.GetArray());

    //Plaintext circuit evaluation on 0 input
    std::vector<bool> evals(circuit.num_wires);
    //Evaluate the AND gates
    for (int i = 0; i < circuit.num_gates; ++i) {
      Gate& g = circuit.gates[i];
      if (g.type == NOT) {
        evals[g.out_wire] = !evals[g.left_wire];
      } else if (g.type == XOR) {
        evals[g.out_wire] = evals[g.left_wire] ^ evals[g.right_wire];
      } else if (g.type == AND) {
        evals[g.out_wire] = evals[g.left_wire] & evals[g.right_wire];
      }
    }

    uint8_t plaintext_res[BITS_TO_BYTES(circuit.num_out_wires)];
    for (int i = 0; i < circuit.num_out_wires; ++i) {
      if (evals[circuit.out_wires_start + i]) {
        SetBitReversed(i, 1, plaintext_res);
      } else {
        SetBitReversed(i, 0, plaintext_res);
      }
    }

    //Check inputs
    for (int j = 0; j < circuit.num_out_wires; ++j) {
      uint8_t curr_key[CSEC_BYTES];
      XOR_128(curr_key, ConstGarbledCircuit::out_key_commit0(circuit, const_curr_session_aux_info.GetArray(), j), ConstGarbledCircuit::out_key_commit1(circuit, const_curr_session_aux_info.GetArray(), j));

      XORBit(j,
             GetBit(0, ConstGarbledCircuit::out_bit_commit0(circuit, const_curr_session_aux_info.GetArray(), j)),
             GetBit(0, ConstGarbledCircuit::out_bit_commit1(circuit, const_curr_session_aux_info.GetArray(), j)),
             head_inp_perm_bits_debug.GetArray());

      if (GetBit(j, head_inp_perm_bits_debug.GetArray()) ^
          GetBitReversed(j, plaintext_res)) {
        XOR_128(curr_key, delta_share0);
        XOR_128(curr_key, delta_share1);
      }

      if (j < circuit.const_out_wires_stop) {
        ASSERT_TRUE(std::equal(curr_key, curr_key + CSEC_BYTES, const_output_keys[i][j]));
      }
      if ((j >= circuit.eval_out_wires_start) &&
          (j <  circuit.eval_out_wires_stop)) {
        uint32_t curr_bit_pos = j - circuit.eval_out_wires_start;
        ASSERT_TRUE(std::equal(curr_key, curr_key + CSEC_BYTES, eval_output_keys[i][curr_bit_pos]));
      }
    }
  }
}