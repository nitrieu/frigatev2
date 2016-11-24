#include "test-duplo.h"

TEST_F(TestDuplo, InputBuckets) {
  mr_init_threading();
  Circuit aes_circuit = read_text_circuit("test/data/AES-non-expanded.txt");
  Circuit sha1_circuit = read_text_circuit("test/data/sha-1.txt");

  std::vector<std::pair<std::string, uint32_t>> const_input_components;
  std::vector<std::pair<std::string, uint32_t>> eval_input_components;
  std::future<void> ret_const = std::async(std::launch::async, [this, &aes_circuit, &sha1_circuit, &const_input_components]() {
    duplo_const.Setup();
    duplo_const.PreprocessComponentType("const_aes", aes_circuit, 6, num_execs_components);
    duplo_const.PreprocessComponentType("const_sha1", sha1_circuit, 2, num_execs_components);

    for (int i = 0; i < 6; ++i) {
      const_input_components.emplace_back("const_aes", i);
    }
    for (int i = 0; i < 2; ++i) {
      const_input_components.emplace_back("const_sha1", i);
    }

    duplo_const.PrepareComponents(const_input_components, num_execs_auths);
  });

  std::future<void> ret_eval = std::async(std::launch::async, [this, &aes_circuit, &sha1_circuit, &eval_input_components]() {
    duplo_eval.Setup();
    duplo_eval.PreprocessComponentType("eval_aes", aes_circuit, 6, num_execs_components);
    duplo_eval.PreprocessComponentType("eval_sha1", sha1_circuit, 2, num_execs_components);


    for (int i = 0; i < 6; ++i) {
      eval_input_components.emplace_back("eval_aes", i);
    }
    for (int i = 0; i < 2; ++i) {
      eval_input_components.emplace_back("eval_sha1", i);
    }

    duplo_eval.PrepareComponents(eval_input_components, num_execs_auths);
  });

  ret_const.wait();
  ret_eval.wait();
  mr_end_threading();

  uint32_t num_inp_components = eval_input_components.size();

  //Check circuit bucket and auth solderings
  uint32_t curr_const_inp_pos = 0;
  GarblingHandler gh;
  for (int l = 0; l < num_inp_components; ++l) {
    std::string component_name = std::get<0>(const_input_components[l]);
    uint32_t component_num = std::get<1>(const_input_components[l]);
    Circuit& circuit = duplo_const.string_to_circuit_map[component_name];

    //Read input circuit aux info
    BYTEArrayVector aux_info;
    duplo_const.persistent_storage.ReadBuckets(component_name, AUXDATA, component_num, 1, aux_info);

    //Read input buckets aux info for all const input wires to this circuit
    BYTEArrayVector inp_bucket_solderings;
    duplo_eval.persistent_storage.ReadBuckets(EVAL_INP_BUCKET_PREFIX, SOLDERINGS, curr_const_inp_pos, circuit.num_const_inp_wires, inp_bucket_solderings);
    //Increment inp bucket counter
    curr_const_inp_pos += circuit.num_const_inp_wires;

    uint32_t solderings_size = EvalGarbledCircuit::SolderingsSize(duplo_eval.inp_bucket_circuit);
    uint32_t inp_bucket_size = inp_bucket_solderings.entry_size / solderings_size;

    uint8_t circuit_delta[CSEC_BYTES];
    XOR_128(circuit_delta,
            ConstGarbledCircuit::delta_commit0(circuit, aux_info.GetArray()),
            ConstGarbledCircuit::delta_commit1(circuit, aux_info.GetArray()));

    BYTEArrayVector circuit_perm_bits(BITS_TO_BYTES(circuit.num_const_inp_wires), 1);
    BYTEArrayVector const_inp_vals(BITS_TO_BYTES(circuit.num_const_inp_wires), 1);
    BYTEArrayVector const_input_keys(circuit.num_const_inp_wires, CSEC_BYTES);
    uint8_t curr_inp_bucket_key[CSEC_BYTES];

    uint8_t inp_bucket_delta[CSEC_BYTES];
    uint8_t curr_hash_delta[CSEC_BYTES];
    uint8_t inp_bucket_key_xor_delta[CSEC_BYTES];
    common_tools_const.rnd.GenRnd(const_inp_vals.GetArray(), const_inp_vals.size);
    for (int j = 0; j < circuit.num_const_inp_wires; ++j) {
      //Construct the actual input keys
      XOR_128(const_input_keys[j],
              ConstGarbledCircuit::inp_key_commit0(circuit, aux_info.GetArray(), j),
              ConstGarbledCircuit::inp_key_commit1(circuit, aux_info.GetArray(), j));

      XORBit(j, GetBit(0, ConstGarbledCircuit::inp_bit_commit0(circuit, aux_info.GetArray(), j)),
             GetBit(0, ConstGarbledCircuit::inp_bit_commit1(circuit, aux_info.GetArray(), j)), circuit_perm_bits.GetArray());

      //First set to 0 keys
      if (GetBit(j, circuit_perm_bits.GetArray())) {
        XOR_128(const_input_keys[j], circuit_delta);
      }

      //Then set to inp_val[j] keys
      if (GetBit(j, const_inp_vals.GetArray())) {
        XOR_128(const_input_keys[j], circuit_delta);
      }

      //Check that inp_bucket correctly decodes input
      for (int b = 0; b < inp_bucket_size; ++b) {
        uint8_t* curr_soldering = inp_bucket_solderings[j] + b * solderings_size;

        XOR_128(curr_inp_bucket_key, const_input_keys[j], EvalGarbledCircuit::inp_soldering_no_aux(duplo_eval.inp_bucket_circuit, curr_soldering));

        if (GetLSB(const_input_keys[j])) {
          XOR_128(curr_inp_bucket_key,
                  EvalGarbledCircuit::delta_soldering_no_aux(duplo_eval.inp_bucket_circuit, curr_soldering));
        }

        //This is where we use the circuit_delta to learn the inp_bucket_delta. In a real, honest, execution circuit_delta is unknown and hence the input bucket cannot decode
        XOR_128(inp_bucket_delta, circuit_delta,
                EvalGarbledCircuit::delta_soldering_no_aux(duplo_eval.inp_bucket_circuit, curr_soldering));

        gh.GarbleInpBucket(curr_hash_delta, inp_bucket_delta, 0);

        if (!GetBit(j, const_inp_vals.GetArray())) {
          ASSERT_TRUE(std::equal(curr_hash_delta, curr_hash_delta + CSEC_BYTES, curr_inp_bucket_key));
        } else {
          XOR_128(inp_bucket_key_xor_delta, curr_inp_bucket_key, inp_bucket_delta);
          ASSERT_TRUE(std::equal(curr_hash_delta, curr_hash_delta + CSEC_BYTES, inp_bucket_key_xor_delta));
        }
      }
    }
  }
}