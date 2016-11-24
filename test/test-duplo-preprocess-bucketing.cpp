#include "test-duplo.h"

TEST_F(TestDuplo, PreprocessBucketing) {
  mr_init_threading();
  Circuit aes_circuit = read_text_circuit("test/data/AES-non-expanded.txt");
  Circuit sha1_circuit = read_text_circuit("test/data/sha-1.txt");
  Circuit sha256_circuit = read_text_circuit("test/data/sha-256.txt");

  std::future<void> ret_const = std::async(std::launch::async, [this, &aes_circuit, &sha1_circuit, &sha256_circuit]() {
    duplo_const.Setup();
    duplo_const.PreprocessComponentType("const_aes", aes_circuit, 50, num_execs_components);
    duplo_const.PreprocessComponentType("const_sha1", sha1_circuit, 2, num_execs_components);
    duplo_const.PreprocessComponentType("const_sha256", sha256_circuit, 10, num_execs_components);
    
    std::vector<std::pair<std::string, uint32_t>> dummy;
    duplo_const.PrepareComponents(dummy, num_execs_auths);
  });

  std::future<void> ret_eval = std::async(std::launch::async, [this, &aes_circuit, &sha1_circuit, &sha256_circuit]() {
    duplo_eval.Setup();
    duplo_eval.PreprocessComponentType("eval_aes", aes_circuit, 50, num_execs_components);
    duplo_eval.PreprocessComponentType("eval_sha1", sha1_circuit, 2, num_execs_components);
    duplo_eval.PreprocessComponentType("eval_sha256", sha256_circuit, 10, num_execs_components);
    
    std::vector<std::pair<std::string, uint32_t>> dummy;
    duplo_eval.PrepareComponents(dummy, num_execs_auths);
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
    uint64_t session_num_buckets = std::get<2>(duplo_const.circuit_info[l]);

    BYTEArrayVector const_curr_session_aux_info;
    duplo_const.persistent_storage.ReadBuckets(const_session_component_type, AUXDATA, 0, session_num_buckets, const_curr_session_aux_info);

    BYTEArrayVector eval_curr_session_aux_info;
    duplo_eval.persistent_storage.ReadBuckets(eval_session_component_type, AUXDATA, 0, session_num_buckets, eval_curr_session_aux_info);

    for (int i = 0; i < session_num_buckets; ++i) {
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
  
  //Check circuit bucket and auth solderings
  for (int l = 0; l < num_sessions; ++l) {
    std::string const_session_component_type(std::get<0>(duplo_const.circuit_info[l]));
    Circuit& session_circuit = std::get<1>(duplo_const.circuit_info[l]);
    uint64_t session_num_buckets = std::get<2>(duplo_const.circuit_info[l]);

    uint32_t constr_aux_size = ConstGarbledCircuit::AuxDataSize(session_circuit);

    BYTEArrayVector exec_permuted_aux_info;

    duplo_const.persistent_storage.ReadBuckets(const_session_component_type, AUXDATA, 0, session_num_buckets, exec_permuted_aux_info);

    BYTEArrayVector input_keys_debug(session_num_buckets * session_circuit.num_inp_wires, CSEC_BYTES);
    uint8_t head_delta_debug[CSEC_BYTES];
    BYTEArrayVector head_inp_perm_bits_debug(BITS_TO_BYTES(session_circuit.num_inp_wires), 1);
    uint32_t curr_head_circuit;
    for (int i = 0; i < session_num_buckets; ++i) {
      curr_head_circuit = i;

      XOR_128(head_delta_debug,
              ConstGarbledCircuit::delta_commit0(session_circuit, exec_permuted_aux_info[curr_head_circuit]),
              ConstGarbledCircuit::delta_commit1(session_circuit, exec_permuted_aux_info[curr_head_circuit]));

      for (int j = 0; j < session_circuit.num_inp_wires; ++j) {
        XOR_128(input_keys_debug[i * session_circuit.num_inp_wires + j],
                ConstGarbledCircuit::inp_key_commit0(session_circuit, exec_permuted_aux_info[curr_head_circuit], j),
                ConstGarbledCircuit::inp_key_commit1(session_circuit, exec_permuted_aux_info[curr_head_circuit], j));

        XORBit(j, GetBit(0, ConstGarbledCircuit::inp_bit_commit0(session_circuit, exec_permuted_aux_info[curr_head_circuit], j)),
               GetBit(0, ConstGarbledCircuit::inp_bit_commit1(session_circuit, exec_permuted_aux_info[curr_head_circuit], j)), head_inp_perm_bits_debug.GetArray());
        if (GetBit(j, head_inp_perm_bits_debug.GetArray())) {
          XOR_128(input_keys_debug[i * session_circuit.num_inp_wires + j], head_delta_debug);
        }
      }
    }

    //Eval side
    std::string eval_session_component_type(std::get<0>(duplo_eval.circuit_info[l]));
    uint32_t garbled_table_size = GarbledCircuit::TotalTableSize(session_circuit);
    uint32_t solderings_size = EvalGarbledCircuit::SolderingsSize(session_circuit);

    BYTEArrayVector exec_read_garbled_buckets;
    BYTEArrayVector exec_read_bucket_solderings;

    duplo_eval.persistent_storage.ReadBuckets(eval_session_component_type, TABLES, 0, session_num_buckets, exec_read_garbled_buckets);
    duplo_eval.persistent_storage.ReadBuckets(eval_session_component_type, SOLDERINGS, 0, session_num_buckets, exec_read_bucket_solderings);

    uint32_t bucket_size = exec_read_garbled_buckets.entry_size / garbled_table_size;
    uint32_t exec_num_total_eval_circuits = session_num_buckets * bucket_size;

    BYTEArrayVector exec_read_garbled_tables(exec_num_total_eval_circuits, garbled_table_size);
    std::copy(exec_read_garbled_buckets.GetArray(), exec_read_garbled_buckets.GetArray() + exec_read_garbled_buckets.size, exec_read_garbled_tables.GetArray());
    BYTEArrayVector exec_read_solderings(exec_num_total_eval_circuits, solderings_size);
    std::copy(exec_read_bucket_solderings.GetArray(), exec_read_bucket_solderings.GetArray() + exec_read_bucket_solderings.size, exec_read_solderings.GetArray());

    BYTEArrayVector head_out_keys_debug(session_circuit.num_out_wires, CSEC_BYTES);
    BYTEArrayVector current_input_keys_debug(session_circuit.num_inp_wires, CSEC_BYTES);
    BYTEArrayVector out_keys_debug(session_circuit.num_out_wires, CSEC_BYTES);
    GarbledCircuit gc_debug(session_circuit, 1);
    GarblingHandler gh;
    bool success = true;
    uint32_t curr_circuit;

    for (int i = 0; i < session_num_buckets; ++i) {
      curr_head_circuit = i * bucket_size;

      gh.EvalGarbledCircuitSolderings(input_keys_debug[i * session_circuit.num_inp_wires], session_circuit, exec_read_garbled_tables[curr_head_circuit], exec_read_solderings[curr_head_circuit], head_out_keys_debug.GetArray());

      for (int l = 1; l < bucket_size; ++l) {
        curr_circuit = curr_head_circuit + l;

        gh.EvalGarbledCircuitSolderings(input_keys_debug[i * session_circuit.num_inp_wires], session_circuit, exec_read_garbled_tables[curr_circuit], exec_read_solderings[curr_circuit], out_keys_debug.GetArray());

        //All bucket_size circuits of current_bucket output the same keys!
        ASSERT_TRUE(std::equal(head_out_keys_debug.GetArray(), head_out_keys_debug.GetArray() + session_circuit.num_out_wires * CSEC_BYTES, out_keys_debug.GetArray()));
      }

      //////////////////////Check Authenticators//////////////////////
      BYTEArrayVector bucket_auths;
      duplo_eval.persistent_storage.ReadBuckets(eval_session_component_type, AUTHS, i * session_circuit.num_out_wires, session_circuit.num_out_wires, bucket_auths);
      BYTEArrayVector auth_ids;
      duplo_eval.persistent_storage.ReadBuckets(eval_session_component_type, AUTHS_IDS, i * session_circuit.num_out_wires, session_circuit.num_out_wires, auth_ids);

      uint32_t auth_size = bucket_auths.entry_size / (2 * CSEC_BYTES);

      BYTEArrayVector bucket_auths_solderings;
      duplo_eval.persistent_storage.ReadBuckets(eval_session_component_type, AUTHS_SOLDERINGS, i * session_circuit.num_out_wires, session_circuit.num_out_wires, bucket_auths_solderings);

      BYTEArrayVector read_delta_solderings;
      duplo_eval.persistent_storage.ReadBuckets(eval_session_component_type, AUTHS_DELTA_SOLDERINGS, i, 1, read_delta_solderings);
      uint8_t* delta_soldering = read_delta_solderings.GetArray();

      uint8_t soldered_output[CSEC_BYTES];
      for (int j = 0; j < session_circuit.num_out_wires; ++j) {
        for (int a = 0; a < auth_size; ++a) {
          std::copy(out_keys_debug[j], out_keys_debug[j + 1], soldered_output);
          if (GetLSB(out_keys_debug[j])) {
            XOR_128(soldered_output, delta_soldering);
          }
          XOR_128(soldered_output, bucket_auths_solderings[j] + a * CSEC_BYTES);
          //All auth_size authenticators of current_bucket authenticate the produced output key
          uint32_t id = *(uint32_t*) (auth_ids[j] + a * sizeof(uint32_t));

          ASSERT_TRUE(VerifyAuth(soldered_output, bucket_auths[j] + 2 * a * CSEC_BYTES, bucket_auths[j] + (2 * a + 1) * CSEC_BYTES, id, gh.key_schedule));

        }
      }
    }
  }
}