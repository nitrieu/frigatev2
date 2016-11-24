#include "frigate-duplo/frigate-duplo-evaluator.h"

FrigateDuploEvaluator::FrigateDuploEvaluator(CommonTools& common_tools, uint32_t num_max_parallel_execs)
	: FrigateDuplo(common_tools, num_max_parallel_execs)
	,
  ot_rec(common_tools),
  commit_seed_OTs(NUM_COMMIT_SEED_OT, CSEC_BYTES),
  commit_seed_choices(BITS_TO_BYTES(NUM_COMMIT_SEED_OT), 1) {
}

void FrigateDuploEvaluator::Setup() {

  ot_rec.InitOTReceiver();

  //OTX for commitment seeds
  ot_rec.Receive(NUM_COMMIT_SEED_OT, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());

  for (int i = 0; i < NUM_COMMIT_SEED_OT; ++i) {
    common_tools.crypt.hash(commit_seed_OTs[i], CSEC_BYTES, commit_seed_OTs[i], CSEC_BYTES);
  }
}

void FrigateDuploEvaluator::PreprocessComponentType(std::string component_type, Circuit& circuit, uint32_t num_buckets, uint32_t num_parallel_execs, BucketType bucket_type) {

  string_to_circuit_map.emplace(component_type, circuit);

  //Compute parameters
  long double check_factor;
  uint32_t bucket_size;
  bool negate_check_factor;

  auto t_param_start = GET_TIME();
  if (bucket_type == SINGLE) {
    FindBestSingleParams(num_buckets, bucket_size, check_factor, negate_check_factor);
  } else if (bucket_type == MAJORITY) {
    FindBestMajorityParams(num_buckets, bucket_size, check_factor, negate_check_factor, 1); //We always catch a bad component
  }
  auto t_param_end = GET_TIME();

#ifdef DUPLO_PRINT

  PrintTimePerBucket(t_param_start, t_param_end, num_buckets, "FindParam");

  //For printing
  double cnc_check_prob;
  if (negate_check_factor) {
    cnc_check_prob = 1 - (1 / pow(2, check_factor));
  } else {
    cnc_check_prob = (1 / pow(2, check_factor));
  }

  std::cout << "bucket_size=" << bucket_size << ", " << "cnc_check_prob=" << cnc_check_prob << std::endl;
#endif

  auto commit_cnc_begin = GET_TIME();

  uint32_t num_eval_circuits = bucket_size * num_buckets;

  std::vector<std::future<void>> execs_finished(num_parallel_execs);

  std::vector<int> eval_circuits_from, eval_circuits_to, buckets_from, buckets_to, prg_counters;

  PartitionBufferFixedNum(buckets_from, buckets_to, num_parallel_execs, num_buckets);
  PartitionBufferFixedNum(eval_circuits_from, eval_circuits_to, num_parallel_execs, num_eval_circuits);

  std::vector<EvalGarbledCircuit> aux_garbled_circuits_data(num_eval_circuits, EvalGarbledCircuit(circuit, 0));
  BYTEArrayVector eval_hash(num_eval_circuits, HASH_BYTES);

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    prg_counters.emplace_back(0); //TODO: compute the right offset for this execution. Will depend on total_circuits_to[i] - total_circuits_from[i] and previous calls to PreprocessComponentType.
    int exec_prg_counter = prg_counters[exec_id];

    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &aux_garbled_circuits_data, &eval_hash, &eval_circuits_from, &eval_circuits_to, exec_id, &circuit, exec_prg_counter, check_factor, negate_check_factor] (int id) {

      uint32_t exec_num_buckets = eval_circuits_to[exec_id] - eval_circuits_from[exec_id];

      float slack_val, repl_factor;
      ComputeCheckFraction(check_factor, exec_num_buckets, slack_val, repl_factor, negate_check_factor);

      uint32_t exec_num_total_circuits = ceil(repl_factor * exec_num_buckets);

      CommitReceiveAndCutAndChoose(exec_common_tools, circuit, exec_num_total_circuits, exec_prg_counter, check_factor, negate_check_factor, eval_circuits_from[exec_id], eval_circuits_to[exec_id], aux_garbled_circuits_data, eval_hash);
    });
  }

  for (std::future<void>& r : execs_finished) {
    r.wait();
  }

  circuit_info.emplace_back(std::make_tuple(component_type, circuit, num_buckets));

  auto commit_cnc_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(commit_cnc_begin, commit_cnc_end, num_buckets, "CommitCNC");
#endif

  auto prepare_files_begin = GET_TIME();

  uint64_t tables_bytes = GarbledCircuit::TotalTableSize(circuit) * num_eval_circuits;
  uint64_t solderings_bytes = EvalGarbledCircuit::SolderingsSize(circuit) * num_eval_circuits;
  uint64_t auxdata_bytes = EvalGarbledCircuit::AuxDataSize(circuit) * num_buckets;

  persistent_storage.PrepareFile(component_type, TABLES, tables_bytes);
  persistent_storage.PrepareFile(component_type, SOLDERINGS, solderings_bytes);
  persistent_storage.PrepareFile(component_type, AUXDATA, auxdata_bytes);

  auto prepare_files_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(prepare_files_begin, prepare_files_end, num_buckets, "PrepareFiles");
#endif

  auto sample_perm_begin = GET_TIME();

  uint8_t bucket_seed[CSEC_BYTES];
  common_tools.rnd.GenRnd(bucket_seed, CSEC_BYTES);
  common_tools.chan.Send(bucket_seed, CSEC_BYTES);

  std::vector<uint32_t> permuted_eval_ids(num_eval_circuits);
  std::vector<uint32_t> permuted_eval_ids_inv(num_eval_circuits);
  std::iota(std::begin(permuted_eval_ids), std::end(permuted_eval_ids), 0);
  PermuteArray(permuted_eval_ids.data(), num_eval_circuits, bucket_seed);
  for (int i = 0; i < num_eval_circuits; ++i) {
    permuted_eval_ids_inv[permuted_eval_ids[i]] = i;
  }
  auto sample_perm_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(sample_perm_begin, sample_perm_end, num_buckets, "SamplePerm");
#endif

  auto circuit_bucketing_begin = GET_TIME();

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {
    int exec_prg_counter = prg_counters[exec_id];
    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &aux_garbled_circuits_data, &eval_hash, &buckets_from, &buckets_to, exec_id, &circuit, bucket_size, &permuted_eval_ids_inv, &component_type] (int id) {

      uint32_t exec_num_buckets = buckets_to[exec_id] - buckets_from[exec_id];

      BucketAndReceiveEvalCircuits(component_type, exec_common_tools, circuit, bucket_size, permuted_eval_ids_inv, buckets_from[exec_id], exec_num_buckets, aux_garbled_circuits_data, eval_hash);
    });
  }

  for (std::future<void>& r : execs_finished) {
    r.wait();
  }

  uint8_t dummy;
  common_tools.chan.Send(&dummy, 1);

  auto circuit_bucketing_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(circuit_bucketing_begin, circuit_bucketing_end, num_buckets, "CircuitBucketing");
#endif
}

void FrigateDuploEvaluator::PrepareEvaluation(std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t num_parallel_execs) {

  CommonTools& inp_common_tools = *common_tools_vec.back();
  std::future<void> eval_input_preparation = thread_pool.push([this, &inp_common_tools, &input_components] (int id) {
    PreprocessInputs(inp_common_tools, input_components);
    DecommitEvalPermBits(inp_common_tools, input_components);
  });

  uint64_t num_circuit_buckets = 0;
  uint64_t num_auth_buckets = 0;

  for (std::tuple<std::string, Circuit, uint64_t>& c_info : circuit_info) {
    num_circuit_buckets += std::get<2>(c_info);
    num_auth_buckets += std::get<2>(c_info) * std::get<1>(c_info).num_out_wires;
  }

  std::vector<std::future<void>> execs_finished(num_parallel_execs);

  //Compute parameters
  long double check_factor;
  uint32_t auth_size;
  bool negate_check_factor;

  auto t_param_start = GET_TIME();
  FindBestMajorityParams(num_auth_buckets, auth_size, check_factor, negate_check_factor, 2);
  auto t_param_end = GET_TIME();

#ifdef DUPLO_PRINT

  PrintTimePerBucket(t_param_start, t_param_end, num_circuit_buckets, "FindAuthParam");

  double cnc_check_prob;
  if (negate_check_factor) {
    cnc_check_prob = 1 - (1 / pow(2, check_factor));
  } else {
    cnc_check_prob = (1 / pow(2, check_factor));
  }

  std::cout << "auth_size=" << auth_size << ", " << "cnc_check_prob=" << cnc_check_prob << std::endl;
#endif
  auto commit_cnc_begin = GET_TIME();

  uint32_t num_eval_auths = num_auth_buckets * auth_size;
  std::vector<int> eval_auths_from, eval_auths_to;
  PartitionBufferFixedNum(eval_auths_from, eval_auths_to, num_parallel_execs, num_eval_auths);

  BYTEArrayVector aux_auth_data(num_eval_auths, CODEWORD_BYTES);
  std::vector<BYTEArrayVector> eval_auths(num_eval_auths, BYTEArrayVector(2, CSEC_BYTES));
  std::vector<uint32_t> eval_auths_ids(num_eval_auths);
  uint8_t aux_auth_delta_data[CODEWORD_BYTES];

  std::mutex delta_updated_mutex;
  std::condition_variable delta_updated_cond_val;
  bool delta_updated = false;
  std::tuple<std::mutex&, std::condition_variable&, bool&> delta_signal = make_tuple(std::ref(delta_updated_mutex), std::ref(delta_updated_cond_val), std::ref(delta_updated));

  std::vector<int> prg_counters;

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    prg_counters.emplace_back(0); //TODO: compute the right offset for this execution. Will depend on total_circuits_to[i] - total_circuits_from[i] + other things.
    int exec_prg_counter = prg_counters[exec_id];

    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();
    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &eval_auths, &aux_auth_data, &eval_auths_ids, &aux_auth_delta_data, &delta_signal, &eval_auths_from, &eval_auths_to, exec_id, exec_prg_counter, check_factor, negate_check_factor] (int id) {

      //TODO:
      /*
      - Compute Input Authenticators for all input wires.
      - Needed to ensure we receive the correct key, needed for both constructor inputs and evaluator inputs.
      - Includes Garbling/cut-and-choose and bucketing. Most, if not all, code of CommitAuthAndCutAndChoose + BucketAllAuths can be reused, but for these components in input_components only.

      - Compute InputBuckets for the input wires of the constructor.
      - Needed to ensure input recovery using Delta as a trapdoor.
      - If no cheating detected these will be left unused in the online phase.
      */
      uint32_t exec_num_auths = eval_auths_to[exec_id] - eval_auths_from[exec_id];

      float slack_val, repl_factor;
      ComputeCheckFraction(check_factor, exec_num_auths, slack_val, repl_factor, negate_check_factor);

      uint32_t exec_num_total_auths = ceil(repl_factor * exec_num_auths);

      CommitAuthAndCutAndChoose(exec_common_tools, exec_num_total_auths, exec_prg_counter, check_factor, negate_check_factor, eval_auths_from[exec_id], eval_auths_to[exec_id], eval_auths, aux_auth_data, eval_auths_ids, aux_auth_delta_data, delta_signal);
    });
  }

  for (std::future<void>& r : execs_finished) {
    r.wait();
  }

  eval_input_preparation.wait(); //Be sure input preparation also finished

  auto commit_cnc_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(commit_cnc_begin, commit_cnc_end, num_circuit_buckets, "AuthCommitCNC");
#endif

  auto sample_perm_begin = GET_TIME();

  std::vector<std::vector<int>> session_circuit_buckets_from(num_parallel_execs);
  std::vector<std::vector<int>> session_circuit_buckets_to(num_parallel_execs);

  for (int i = 0; i < circuit_info.size(); ++i) {
    std::string& session_component_name(std::get<0>(circuit_info[i]));
    Circuit& session_circuits(std::get<1>(circuit_info[i]));
    uint64_t num_session_circuit_buckets = std::get<2>(circuit_info[i]);

    uint64_t num_session_auth_buckets = num_session_circuit_buckets * session_circuits.num_out_wires;
    uint64_t session_auth_bytes = 2 * CSEC_BYTES * num_session_auth_buckets * auth_size;
    uint64_t session_auth_soldeirngs_bytes = CSEC_BYTES * num_session_auth_buckets * auth_size;
    uint64_t session_auth_delta_solderings_bytes = CSEC_BYTES * num_session_circuit_buckets;
    uint64_t session_auth_ids_bytes = sizeof(uint32_t) * num_session_auth_buckets * auth_size;

    std::vector<int> tmp_from, tmp_to;
    PartitionBufferFixedNum(tmp_from, tmp_to, num_parallel_execs, num_session_circuit_buckets);
    for (int j = 0; j < num_parallel_execs; ++j) {
      session_circuit_buckets_from[j].push_back(tmp_from[j]);
      session_circuit_buckets_to[j].push_back(tmp_to[j]);
    }

    persistent_storage.PrepareFile(session_component_name, AUTHS, session_auth_bytes);
    persistent_storage.PrepareFile(session_component_name, AUTHS_SOLDERINGS, session_auth_soldeirngs_bytes);
    persistent_storage.PrepareFile(session_component_name, AUTHS_DELTA_SOLDERINGS, session_auth_delta_solderings_bytes);
    persistent_storage.PrepareFile(session_component_name, AUTHS_IDS, session_auth_ids_bytes);
  }


  uint8_t bucket_seed[CSEC_BYTES];
  common_tools.rnd.GenRnd(bucket_seed, CSEC_BYTES);
  common_tools.chan.Send(bucket_seed, CSEC_BYTES);

  std::vector<uint32_t> permuted_eval_ids(num_eval_auths);
  std::vector<uint32_t> permuted_eval_ids_inv(num_eval_auths);
  std::iota(std::begin(permuted_eval_ids), std::end(permuted_eval_ids), 0);
  PermuteArray(permuted_eval_ids.data(), num_eval_auths, bucket_seed);
  for (int i = 0; i < num_eval_auths; ++i) {
    permuted_eval_ids_inv[permuted_eval_ids[i]] = i;
  }

  auto sample_perm_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(sample_perm_begin, sample_perm_end, num_circuit_buckets, "PrepareFileSampleAuthPerm");
#endif

  auto auth_bucketing_begin = GET_TIME();

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {
    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &eval_auths, &aux_auth_data, &aux_auth_delta_data, &session_circuit_buckets_from, &session_circuit_buckets_to, exec_id, &permuted_eval_ids_inv, &eval_auths_ids, auth_size] (int id) {

      BucketAllAuths(circuit_info, exec_common_tools, auth_size, permuted_eval_ids_inv, session_circuit_buckets_from[exec_id], session_circuit_buckets_to[exec_id], eval_auths, aux_auth_data, eval_auths_ids, aux_auth_delta_data);
    });
  }

  for (std::future<void>& r : execs_finished) {
    r.wait();
  }

  uint8_t dummy;
  common_tools.chan.Send(&dummy, 1);

  auto auth_bucketing_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(auth_bucketing_begin, auth_bucketing_end, num_circuit_buckets, "AuthBucketing");
#endif
}

std::pair<std::string, uint32_t> FrigateDuploEvaluator::SolderGarbledComponents(std::string resulting_component_type, std::vector<std::tuple<std::string, uint32_t, std::vector<uint32_t>>>& input_wire_components, std::vector<std::tuple<std::string, uint32_t, std::vector<uint32_t>>>& output_wire_components, std::vector<std::tuple<std::string, uint32_t, std::vector<uint32_t>>>& resulting_component_out_wires) {

  return std::make_pair("", 0);
}

void FrigateDuploEvaluator::EvalComponents(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& output_keys, uint32_t num_parallel_execs) {

  std::vector<int> components_from, components_to;
  PartitionBufferFixedNum(components_from, components_to, num_parallel_execs, components.size());

  std::vector<std::future<void>> futures;

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    //Find out how many input wires
    uint32_t num_total_eval_inputs = 0;
    for (int i = components_from[exec_id]; i < components_to[exec_id]; ++i) {
      std::string component_name = std::get<0>(components[i]);
      Circuit& circuit = string_to_circuit_map[component_name];
      num_total_eval_inputs += circuit.num_eval_inp_wires;
    }

    //Increment counters and store current position
    uint32_t exec_inputs_used = inputs_used;
    inputs_used += num_total_eval_inputs;

    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    futures.emplace_back(thread_pool.push([this, &exec_common_tools, &components, &components_from, &components_to, &inputs, &output_keys, exec_inputs_used, num_parallel_execs, exec_id] (int id) {

      uint32_t exec_num_components = components_to[exec_id] - components_from[exec_id];

      //Construct aux information
      std::vector<uint32_t> eval_inp_sizes, const_inp_sizes, eval_inp_pos, const_inp_pos;
      std::vector<BYTEArrayVector> input_keys;
      uint32_t num_total_eval_inputs = 0;
      uint32_t num_total_const_inputs = 0;
      for (int i = components_from[exec_id]; i < components_to[exec_id]; ++i) {
        std::string component_name = std::get<0>(components[i]);
        Circuit& circuit = string_to_circuit_map[component_name];
        input_keys.emplace_back(BYTEArrayVector(circuit.num_inp_wires, CSEC_BYTES));
        eval_inp_pos.emplace_back(num_total_eval_inputs);
        const_inp_pos.emplace_back(num_total_const_inputs);

        num_total_eval_inputs += circuit.num_eval_inp_wires;
        num_total_const_inputs += circuit.num_const_inp_wires;

        eval_inp_sizes.emplace_back(circuit.num_eval_inp_wires);
        const_inp_sizes.emplace_back(circuit.num_const_inp_wires);
      }

      //Rad all input mask data from disk
      BYTEArrayVector input_masks_shares;
      BYTEArrayVector input_mask_corrections;
      BYTEArrayVector input_masks_delta_share;
      BYTEArrayVector input_mask_delta_correction;
      BYTEArrayVector choice_bits(BITS_TO_BYTES(num_total_eval_inputs), 1);
      if (num_total_eval_inputs > 0) {
        persistent_storage.ReadBuckets(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_AUXDATA, exec_inputs_used, num_total_eval_inputs, input_masks_shares);
        persistent_storage.ReadBuckets(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_CORRECTIONS, exec_inputs_used, num_total_eval_inputs, input_mask_corrections);
        persistent_storage.ReadBuckets(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_DELTA_AUXDATA, 0, 1, input_masks_delta_share);
        persistent_storage.ReadBuckets(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_DELTA_CORRECTION, 0, 1, input_mask_delta_correction);
      }

      for (int i = 0; i < num_total_eval_inputs; ++i) {
        if (*(input_masks_shares[i] + CODEWORD_BYTES) == 1) {
          SetBit(i, 1, choice_bits.GetArray());
        }
      }

      //Construct more aux info, construct the choice vector e and the decommit shares
      std::vector<uint8_t> key_shares((num_total_eval_inputs + exec_num_components) * CODEWORD_BYTES);
      uint8_t* eval_keys_start_share = key_shares.data();
      uint8_t* deltas_start_share = eval_keys_start_share + num_total_eval_inputs * CODEWORD_BYTES;

      BYTEArrayVector e(BITS_TO_BYTES(num_total_eval_inputs), 1);
      std::vector<uint8_t*> e_vec(exec_num_components);
      uint32_t inc_pos = 0;
      for (int i = 0; i < exec_num_components; ++i) {
        uint32_t curr_component = components_from[exec_id] + i;
        std::string component_name = std::get<0>(components[curr_component]);
        uint32_t component_num = std::get<1>(components[curr_component]);
        Circuit& circuit = string_to_circuit_map[component_name];

        e_vec[i] = e.GetArray() + inc_pos;
        inc_pos += BITS_TO_BYTES(eval_inp_sizes[i]);

        if (num_total_eval_inputs > 0) {

          //e = y \xor c
          std::copy(inputs[curr_component].begin(), inputs[curr_component].end(), e_vec[i]);
          for (int j = 0; j < eval_inp_sizes[i]; ++j) {
            XORBit(j, GetBit(eval_inp_pos[i] + j, choice_bits.GetArray()), e_vec[i]);
          }

          BYTEArrayVector input_perm_bits;
          uint64_t read_pos = perm_bits_pos_map[std::make_tuple(std::get<0>(components[curr_component]), std::get<1>(components[curr_component]))];

          persistent_storage.ReadBuckets(EVAL_PREPROCESS_PREFIX, INPUT_PERM_BITS, read_pos, BITS_TO_BYTES(eval_inp_sizes[i]), input_perm_bits);

          //e = y \xor c \xor b
          XOR_UINT8_T(e_vec[i], input_perm_bits.GetArray(), BITS_TO_BYTES(eval_inp_sizes[i]));
        }

        //Construct commit shares
        BYTEArrayVector component_aux_data;
        persistent_storage.ReadBuckets(component_name, AUXDATA, component_num, 1, component_aux_data);

        //Construct current component delta soldering share
        std::copy(EvalGarbledCircuit::delta_share(circuit, component_aux_data.GetArray()),
                  EvalGarbledCircuit::delta_share(circuit, component_aux_data.GetArray() + CODEWORD_BYTES),
                  deltas_start_share + i * CODEWORD_BYTES);
        if (num_total_eval_inputs > 0) {
          XOR_CodeWords(deltas_start_share + i * CODEWORD_BYTES, input_masks_delta_share.GetArray());
        }

        //Construct eval input shares
        for (int j = 0; j < eval_inp_sizes[i]; ++j) {
          //First copy eval key share
          std::copy(EvalGarbledCircuit::inp_key_share(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j),
                    EvalGarbledCircuit::inp_key_share(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j + 1),
                    eval_keys_start_share + (eval_inp_pos[i] + j) * CODEWORD_BYTES);

          //XOR with mask key shares
          XOR_CodeWords(eval_keys_start_share + (eval_inp_pos[i] + j) * CODEWORD_BYTES, input_masks_shares[eval_inp_pos[i] + j]);

          //If e_j for this component is set XOR input_mask_delta onto the decommit
          if (GetBit(j, e_vec[i])) {
            XOR_CodeWords(eval_keys_start_share + (eval_inp_pos[i] + j) * CODEWORD_BYTES, input_masks_delta_share.GetArray());
          }
        }
      }

      exec_common_tools.chan.Send(e.GetArray(), e.size);

      std::vector<uint8_t> key_decommits(num_total_const_inputs * CSEC_BYTES +
                                         (num_total_eval_inputs + exec_num_components) * 2 * CODEWORD_BYTES);
      uint8_t* const_keys = key_decommits.data();
      uint8_t* eval_keys_start_share0 = const_keys + num_total_const_inputs * CSEC_BYTES;
      uint8_t* deltas_start_share0 = eval_keys_start_share0 + num_total_eval_inputs * CODEWORD_BYTES;

      uint8_t* eval_keys_start_share1 = deltas_start_share0 + exec_num_components * CODEWORD_BYTES;
      uint8_t* deltas_start_share1 = eval_keys_start_share1 + num_total_eval_inputs * CODEWORD_BYTES;

      exec_common_tools.chan.ReceiveBlocking(key_decommits.data(), key_decommits.size());

      //Check the decommits
      CommitReceiver commit_rec(exec_common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());

      BYTEArrayVector decomitted_inp_values(num_total_eval_inputs, CSEC_BYTES);
      if (!VerifyDecommits(eval_keys_start_share0, eval_keys_start_share1, eval_keys_start_share, decomitted_inp_values.GetArray(), commit_seed_choices.GetArray(), commit_rec.code.get(), num_total_eval_inputs)) {
        std::cout << "Sender fail inp decommit in inp delivery!" << std::endl;
        throw std::runtime_error("Abort, Sender fail inp decommit in inp delivery!");
      }

      BYTEArrayVector decomitted_delta_solderings(exec_num_components, CSEC_BYTES);
      if (!VerifyDecommits(deltas_start_share0, deltas_start_share1, deltas_start_share, decomitted_delta_solderings.GetArray(), commit_seed_choices.GetArray(), commit_rec.code.get(), exec_num_components)) {
        std::cout << "Sender fail delta decommit in inp delivery!" << std::endl;
        throw std::runtime_error("Abort, Sender fail delta decommit in inp delivery!");
      }

      //Compute and store the resulting keys to input_keys
      for (int i = 0; i < exec_num_components; ++i) {
        //Copy const keys
        std::copy(const_keys + const_inp_pos[i] * CSEC_BYTES, const_keys + (const_inp_pos[i] + const_inp_sizes[i]) * CSEC_BYTES, input_keys[i].GetArray());

        for (int j = 0; j < eval_inp_sizes[i]; ++j) {
          std::copy(decomitted_inp_values[eval_inp_pos[i] + j],
                    decomitted_inp_values[eval_inp_pos[i] + j + 1],
                    input_keys[i][const_inp_sizes[i] + j]);
          XOR_128(input_keys[i][const_inp_sizes[i] + j], input_mask_corrections[eval_inp_pos[i] + j]);

          if (GetBit(eval_inp_pos[i] + j, choice_bits.GetArray())) { //choicebits == 1
            XOR_128(input_keys[i][const_inp_sizes[i] + j], input_mask_delta_correction.GetArray());
          }

          if (GetBit(eval_inp_pos[i] + j, choice_bits.GetArray()) ^ GetBit(j, e_vec[i])) { //input_perm bits == 1
            XOR_128(input_keys[i][const_inp_sizes[i] + j], decomitted_delta_solderings[i]);
          }
        }
      }

      if (num_parallel_execs == 1) {
        EvalBucketsParallel(components, components_from[exec_id], components_to[exec_id], input_keys, output_keys);
      } else {
        EvalBucketsSerial(components, components_from[exec_id], components_to[exec_id], input_keys, output_keys);
      }

      // int num_runs = 5;
      // auto serial_start = GET_TIME();
      // for (int i = 0; i < num_runs; ++i) {
      //   EvalBucketsParallel(components, components_from[exec_id], components_to[exec_id], input_keys, output_keys);
      // }
      // auto serial_end = GET_TIME();

      // uint64_t serial_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(serial_end - serial_start).count();
      // std::cout << "Serial per circuit: " << (double) serial_nano / num_runs / exec_num_components / 1000000 << std::endl;

      // auto parallel_start = GET_TIME();
      // for (int i = 0; i < num_runs; ++i) {
      //   EvalBucketsSerial(components, components_from[exec_id], components_to[exec_id], input_keys, output_keys);
      // }
      // auto parallel_end = GET_TIME();


      // uint64_t parallel_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(parallel_end - parallel_start).count();


      // std::cout << "Parallel per circuit: " << (double) parallel_nano / num_runs / exec_num_components / 1000000 << std::endl;

    }));
  }

  for (std::future<void>& future : futures) {
    future.wait();
  }

  uint8_t dummy;
  common_tools.chan.Send(&dummy, 1);
}

void FrigateDuploEvaluator::DecodeWires(std::pair<std::string, uint32_t>& component_type, std::vector<uint32_t>& output_wires, std::vector<uint8_t>& resulting_output) {

}

void FrigateDuploEvaluator::CommitReceiveAndCutAndChoose(CommonTools & exec_common_tools, Circuit & circuit, uint32_t exec_num_total_garbled, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_circuits_from, uint32_t exec_eval_circuits_to, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data, BYTEArrayVector & eval_hash) {

  uint32_t num_inp_keys, num_out_keys, num_deltas, num_commit_keys, num_base_keys, input_keys_idx, output_keys_idx, deltas_idx;
  ComputeIndices(exec_num_total_garbled, circuit, num_inp_keys, num_out_keys, num_deltas, num_commit_keys, num_base_keys, input_keys_idx, output_keys_idx, deltas_idx);

  CommitReceiver commit_rec(exec_common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());
  BitCommitReceiver bit_commit_rec(exec_common_tools, commit_seed_OTs[CODEWORD_BITS], commit_seed_choices[CODEWORD_BYTES]);

  BYTEArrayVector commit_keys_share(num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector commit_lsbs_share(num_base_keys, BIT_CODEWORD_BYTES);

  //Commit to keys
  if (!commit_rec.Commit(num_commit_keys, commit_keys_share, exec_prg_counter, deltas_idx)) {
    std::cout << "Abort, key commit failed!" << std::endl;;
    throw std::runtime_error("Abort, key commit failed!");
  }
  if (!bit_commit_rec.Commit(num_base_keys, commit_lsbs_share, exec_prg_counter)) {
    std::cout << "Abort, lsb commit failed!" << std::endl;;
    throw std::runtime_error("Abort, lsb commit failed!");
  }

  BYTEArrayVector out_wire_commit_corrections(num_out_keys, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(out_wire_commit_corrections.GetArray(), out_wire_commit_corrections.size);

  BYTEArrayVector garb_circuit_hashes(exec_num_total_garbled, HASH_BYTES);
  exec_common_tools.chan.ReceiveBlocking(garb_circuit_hashes.GetArray(), garb_circuit_hashes.size);


  //Sample and send challenge seed
  uint8_t cnc_seed[CSEC_BYTES];
  exec_common_tools.rnd.GenRnd(cnc_seed, CSEC_BYTES);
  exec_common_tools.chan.Send(cnc_seed, CSEC_BYTES);

  //Select challenge circuits based on cnc_seed
  uint32_t num_bytes_exec_num_total_garbled = BITS_TO_BYTES(exec_num_total_garbled);
  std::vector<uint8_t> cnc_check_circuits(num_bytes_exec_num_total_garbled);
  PRNG cnc_rand;
  cnc_rand.SetSeed(cnc_seed);

  WeightedRandomString(cnc_check_circuits.data(), check_factor, num_bytes_exec_num_total_garbled, cnc_rand, negate_check_factor);
  int num_checked_circuits = countSetBits(cnc_check_circuits.data(), 0, exec_num_total_garbled - 1);

  uint32_t cnc_num_inp_keys, cnc_num_out_keys, cnc_num_deltas, cnc_num_commit_keys, cnc_num_base_keys, cnc_input_keys_idx, cnc_output_keys_idx, cnc_deltas_idx;
  ComputeIndices(num_checked_circuits, circuit, cnc_num_inp_keys, cnc_num_out_keys, cnc_num_deltas, cnc_num_commit_keys, cnc_num_base_keys, cnc_input_keys_idx, cnc_output_keys_idx, cnc_deltas_idx);

  BYTEArrayVector cnc_lsbs_share(cnc_num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector cnc_keys_share(cnc_num_commit_keys, CODEWORD_BYTES);

  //We need to do lsb BatchDecommit before we can do key BatchDecommit
  uint32_t current_check_circuit_idx = 0;
  for (int i = 0; i < exec_num_total_garbled; ++i) {
    if (GetBit(i, cnc_check_circuits.data())) { //Checked circuit

      //Add input permutation bits
      std::copy(commit_lsbs_share[input_keys_idx + i * circuit.num_inp_wires], commit_lsbs_share[input_keys_idx + (i + 1) * circuit.num_inp_wires], cnc_lsbs_share[cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires]);

      //Add output permutation bits
      std::copy(commit_lsbs_share[output_keys_idx + i * circuit.num_out_wires], commit_lsbs_share[output_keys_idx + (i + 1) * circuit.num_out_wires], cnc_lsbs_share[cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires]);

      ++current_check_circuit_idx;
    }
  }

  //Receive postulated lsb values
  BYTEArrayVector cnc_commit_lsbs(BITS_TO_BYTES(cnc_num_base_keys), 1);
  exec_common_tools.chan.ReceiveBlocking(cnc_commit_lsbs.GetArray(), cnc_commit_lsbs.size);

  //Batch decommit these values
  if (!bit_commit_rec.BatchDecommit(cnc_lsbs_share.GetArray(), cnc_num_base_keys, cnc_commit_lsbs.GetArray())) {
    std::cout << "Abort, cut-and-choose bit decommit failed!" << std::endl;;
    throw std::runtime_error("Abort, cut-and-choose bit decommit failed!");
  }

  current_check_circuit_idx = 0;
  uint32_t current_eval_circuit_idx = exec_eval_circuits_from;
  bool completed_eval_copy = false;
  for (int i = 0; i < exec_num_total_garbled; ++i) {
    if (GetBit(i, cnc_check_circuits.data())) { //Checked circuit

      //Add delta
      std::copy(commit_keys_share[deltas_idx + i], commit_keys_share[deltas_idx + (i + 1)], cnc_keys_share[cnc_deltas_idx + current_check_circuit_idx]);

      //Add inputs
      std::copy(commit_keys_share[input_keys_idx + i * circuit.num_inp_wires], commit_keys_share[input_keys_idx + (i + 1) * circuit.num_inp_wires], cnc_keys_share[cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires]);
      for (int j = 0; j < circuit.num_inp_wires; ++j) {
        if (GetBit(cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j, cnc_commit_lsbs.GetArray())) {
          XOR_CodeWords(cnc_keys_share[cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j], cnc_keys_share[cnc_deltas_idx + current_check_circuit_idx]);
        }
      }

      //Add outputs
      std::copy(commit_keys_share[output_keys_idx + i * circuit.num_out_wires], commit_keys_share[output_keys_idx + (i + 1) * circuit.num_out_wires], cnc_keys_share[cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires]);
      for (int j = 0; j < circuit.num_out_wires; ++j) {
        if (GetBit(cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j, cnc_commit_lsbs.GetArray())) {
          XOR_CodeWords(cnc_keys_share[cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j], cnc_keys_share[cnc_deltas_idx + current_check_circuit_idx]);
        }
      }

      ++current_check_circuit_idx;
    } else if (current_eval_circuit_idx < exec_eval_circuits_to) {

      //Copy Delta
      std::copy(commit_keys_share[deltas_idx + i], commit_keys_share[deltas_idx + (i + 1)], aux_garbled_circuits_data[current_eval_circuit_idx].delta_share());

      //Copy inputs
      std::copy(commit_keys_share[input_keys_idx + i * circuit.num_inp_wires], commit_keys_share[input_keys_idx + (i + 1) * circuit.num_inp_wires], aux_garbled_circuits_data[current_eval_circuit_idx].inp_key_share());

      //Copy outputs
      std::copy(commit_keys_share[output_keys_idx + i * circuit.num_out_wires], commit_keys_share[output_keys_idx + (i + 1) * circuit.num_out_wires], aux_garbled_circuits_data[current_eval_circuit_idx].out_key_share());

      //Copy input permutation bits
      std::copy(commit_lsbs_share[input_keys_idx + i * circuit.num_inp_wires], commit_lsbs_share[input_keys_idx + (i + 1) * circuit.num_inp_wires], aux_garbled_circuits_data[current_eval_circuit_idx].inp_bit_share());

      //Copy output permutation bits
      std::copy(commit_lsbs_share[output_keys_idx + i * circuit.num_out_wires], commit_lsbs_share[output_keys_idx + (i + 1) * circuit.num_out_wires], aux_garbled_circuits_data[current_eval_circuit_idx].out_bit_share());

      //Add output correction
      std::copy(out_wire_commit_corrections[i * circuit.num_out_wires], out_wire_commit_corrections[(i + 1) * circuit.num_out_wires], aux_garbled_circuits_data[current_eval_circuit_idx].out_soldering());

      ++current_eval_circuit_idx;
    } else {
      completed_eval_copy = true;
    }
  }

  if (!completed_eval_copy) {
    std::cout << "Problem. Not enough eval circuits! Params should be set so this never occurs" << std::endl;
  }

  BYTEArrayVector cnc_keys(cnc_num_commit_keys, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(cnc_keys.GetArray(), cnc_keys.size);

  if (!commit_rec.BatchDecommit(cnc_keys_share.GetArray(), cnc_num_commit_keys, cnc_keys.GetArray())) {
    std::cout << "Abort, cut-and-choose decommit failed!" << std::endl;
    throw std::runtime_error("Abort, cut-and-choose decommit failed!");
  }


  GarblingHandler gh;
  std::vector<EvalGarbledCircuit> cnc_garbled_circuits(num_checked_circuits, EvalGarbledCircuit(circuit));

  BYTEArrayVector cnc_garb_circuit_hashes(num_checked_circuits, HASH_BYTES);
  BYTEArrayVector output_keys(circuit.num_out_wires, CSEC_BYTES);
  BYTEArrayVector decommitted_output_keys(circuit.num_out_wires, CSEC_BYTES);

  current_check_circuit_idx = 0; //reset counter
  current_eval_circuit_idx = exec_eval_circuits_from; //reset counter
  for (int i = 0; i < exec_num_total_garbled; ++i) {
    if (GetBit(i, cnc_check_circuits.data())) {
      //Garble the circuit and store output keys to output_keys
      gh.GarbleCircuit(cnc_keys[cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires], output_keys.GetArray(), cnc_keys[cnc_deltas_idx + current_check_circuit_idx], cnc_garbled_circuits[current_check_circuit_idx]);

      //Compute the decomitted output wires using out_wire_commit_corrections and the decomitted values in cnc_keys
      for (int j = 0; j < circuit.num_out_wires; ++j) {
        XOR_128(decommitted_output_keys[j], out_wire_commit_corrections[i * circuit.num_out_wires + j], cnc_keys[cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j]);
      }

      //Check that the computed output keys match the decomitted ones
      if (!std::equal(output_keys.GetArray(), output_keys[circuit.num_out_wires - 1], decommitted_output_keys.GetArray())) {
        std::cout << "Abort, garbled circuit wrong output commits!" << std::endl;
        throw std::runtime_error("Abort, garbled circuit wrong output commits!");
      }

      //Finally check that the comitted tables match the cnc constructed tables by comparing the hash
      exec_common_tools.crypt.hash(cnc_garb_circuit_hashes[current_check_circuit_idx], HASH_BYTES, cnc_garbled_circuits[current_check_circuit_idx].GetTables(), cnc_garbled_circuits[current_check_circuit_idx].size);

      if (!std::equal(cnc_garb_circuit_hashes[current_check_circuit_idx], cnc_garb_circuit_hashes[current_check_circuit_idx] + HASH_BYTES, garb_circuit_hashes[i])) {

        std::cout << "Abort, garbled tables wrongly constructed. Hash doesn't match!" << std::endl;
        throw std::runtime_error("Abort, garbled tables wrongly constructed. Hash doesn't match!");
      }
      ++current_check_circuit_idx;
    } else if (current_eval_circuit_idx < exec_eval_circuits_to) {
      std::copy(garb_circuit_hashes[i], garb_circuit_hashes[i + 1], eval_hash[current_eval_circuit_idx]);

      ++current_eval_circuit_idx;
    }
  }
}

void FrigateDuploEvaluator::BucketAndReceiveEvalCircuits(std::string component_type, CommonTools & exec_common_tools, Circuit & circuit, uint32_t bucket_size, std::vector<uint32_t>& permuted_eval_ids_inv, uint32_t exec_buckets_from, uint32_t exec_num_buckets, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data, BYTEArrayVector & eval_hash) {

  uint64_t exec_num_eval_circuits = exec_num_buckets * bucket_size;

  uint64_t garbled_table_size = GarbledCircuit::TotalTableSize(circuit);
  uint64_t solderings_size = EvalGarbledCircuit::SolderingsSize(circuit);
  uint64_t eval_aux_size = EvalGarbledCircuit::AuxDataSize(circuit);
  uint64_t total_eval_aux_size = EvalGarbledCircuit::TotalAuxDataSize(circuit);


  //Receive all garbled tables
  BYTEArrayVector exec_received_garbled_tables(exec_num_eval_circuits, garbled_table_size);

  exec_common_tools.chan.ReceiveBlocking(exec_received_garbled_tables.GetArray(), exec_received_garbled_tables.size);

  BYTEArrayVector exec_write_head_auxdata(exec_num_buckets, eval_aux_size); //Does not include space for solderings as this will be part of exec_write_solderings array
  BYTEArrayVector exec_write_solderings(exec_num_eval_circuits, solderings_size);

  BYTEArrayVector exec_permuted_aux_info(exec_num_eval_circuits, total_eval_aux_size);

  uint8_t hash_value[HASH_BYTES] = {0};
  for (int i = 0; i < exec_num_eval_circuits; ++i) {
    uint32_t global_circuit_index = exec_buckets_from * bucket_size + i;

    std::copy(aux_garbled_circuits_data[permuted_eval_ids_inv[global_circuit_index]].GetAuxArray(),
              aux_garbled_circuits_data[permuted_eval_ids_inv[global_circuit_index]].GetAuxArray() + total_eval_aux_size,
              exec_permuted_aux_info[i]);

    exec_common_tools.crypt.hash(hash_value, HASH_BYTES, exec_received_garbled_tables[i], garbled_table_size);
    if (!std::equal(hash_value, hash_value + HASH_BYTES, eval_hash[permuted_eval_ids_inv[global_circuit_index]])) {
      std::cout << "Abort, wrong eval garbled tables sent. Hash doesn't match!" << std::endl;
      throw std::runtime_error("Abort, wrong eval garbled tables sent. Hash doesn't match!");
    }
  }

  ////////////////////////////Soldering/////////////////////////////////////

  uint32_t num_soldering_circuits = (bucket_size - 1) * exec_num_eval_circuits;

  uint32_t solder_num_inp_keys, solder_num_out_keys, solder_num_deltas, solder_num_commit_keys, solder_num_base_keys, solder_input_keys_idx, solder_output_keys_idx, solder_deltas_idx;
  ComputeIndices(num_soldering_circuits, circuit, solder_num_inp_keys, solder_num_out_keys, solder_num_deltas, solder_num_commit_keys, solder_num_base_keys, solder_input_keys_idx, solder_output_keys_idx, solder_deltas_idx);

  BYTEArrayVector solder_keys_share(solder_num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector solder_lsbs_share(solder_num_base_keys, BIT_CODEWORD_BYTES);

  int curr_head_circuit, curr_circuit, curr_solder_read_pos;
  for (int i = 0; i < exec_num_buckets; ++i) {
    curr_head_circuit = i * bucket_size;

    for (int l = 1; l < bucket_size; ++l) {
      curr_circuit = curr_head_circuit + l;
      curr_solder_read_pos = curr_circuit - (i + 1);

      //Add delta decommits
      std::copy(EvalGarbledCircuit::delta_share(circuit, exec_permuted_aux_info[curr_circuit]),
                EvalGarbledCircuit::delta_share(circuit, exec_permuted_aux_info[curr_circuit] + CODEWORD_BYTES),
                solder_keys_share[solder_deltas_idx + curr_solder_read_pos]);
      XOR_CodeWords(solder_keys_share[solder_deltas_idx + curr_solder_read_pos], EvalGarbledCircuit::delta_share(circuit, exec_permuted_aux_info[curr_head_circuit]));

      for (int j = 0; j < circuit.num_inp_wires; ++j) {

        //Add input decommits
        std::copy(EvalGarbledCircuit::inp_key_share(circuit, exec_permuted_aux_info[curr_circuit], j),
                  EvalGarbledCircuit::inp_key_share(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_keys_share[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j]);
        XOR_CodeWords(solder_keys_share[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j], EvalGarbledCircuit::inp_key_share(circuit, exec_permuted_aux_info[curr_head_circuit], j));

        //Add input permutation bit soldering decommit
        std::copy(EvalGarbledCircuit::inp_bit_share(circuit, exec_permuted_aux_info[curr_circuit], j),
                  EvalGarbledCircuit::inp_bit_share(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_lsbs_share[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j]);
        XOR_BitCodeWords(solder_lsbs_share[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j], EvalGarbledCircuit::inp_bit_share(circuit, exec_permuted_aux_info[curr_head_circuit], j));
      }

      for (int j = 0; j < circuit.num_out_wires; ++j) {
        //Add output decommits
        std::copy(EvalGarbledCircuit::out_key_share(circuit, exec_permuted_aux_info[curr_circuit], j),
                  EvalGarbledCircuit::out_key_share(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_keys_share[solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j]);
        XOR_CodeWords(solder_keys_share[solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j], EvalGarbledCircuit::out_key_share(circuit, exec_permuted_aux_info[curr_head_circuit], j));

        //Add output permutation bit soldering decommit
        std::copy(EvalGarbledCircuit::out_bit_share(circuit, exec_permuted_aux_info[curr_circuit], j),
                  EvalGarbledCircuit::out_bit_share(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_lsbs_share[solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j]);
        XOR_BitCodeWords(solder_lsbs_share[solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j], EvalGarbledCircuit::out_bit_share(circuit, exec_permuted_aux_info[curr_head_circuit], j));
      }
    }
  }

  CommitReceiver commit_rec(exec_common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());
  BitCommitReceiver bit_commit_rec(exec_common_tools, commit_seed_OTs[CODEWORD_BITS], commit_seed_choices[CODEWORD_BYTES]);


  BYTEArrayVector solder_commit_lsbs(BITS_TO_BYTES(solder_num_base_keys), 1);

  //Receive postulated lsb values
  exec_common_tools.chan.ReceiveBlocking(solder_commit_lsbs.GetArray(), solder_commit_lsbs.size);

  //Batch decommit these values
  if (!bit_commit_rec.BatchDecommit(solder_lsbs_share.GetArray(), solder_num_base_keys, solder_commit_lsbs.GetArray())) {
    std::cout << "Abort, soldering bit decommit failed!" << std::endl;;
    throw std::runtime_error("Abort, soldering bit decommit failed!");
  }

  //Using the decomitted bits in solder_commit_lsbs.GetArray(), correct each soldering share to potentially include delta.
  for (int i = 0; i < exec_num_buckets; ++i) {
    curr_head_circuit = i * bucket_size;

    for (int l = 1; l < bucket_size; ++l) {
      curr_circuit = curr_head_circuit + l;
      curr_solder_read_pos = curr_circuit - (i + 1);

      for (int j = 0; j < circuit.num_inp_wires; ++j) {

        //Add input decommits
        if (GetBit(solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j, solder_commit_lsbs.GetArray())) {
          XOR_CodeWords(solder_keys_share[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j], EvalGarbledCircuit::delta_share(circuit, exec_permuted_aux_info[curr_circuit]));
        }
      }

      for (int j = 0; j < circuit.num_out_wires; ++j) {
        //Add output decommits
        if (GetBit(solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j, solder_commit_lsbs.GetArray())) {
          XOR_CodeWords(solder_keys_share[solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j], EvalGarbledCircuit::delta_share(circuit, exec_permuted_aux_info[curr_circuit]));
        }
      }
    }
  }
  //Receive the postulated solderings and check correctness using batch decommit
  BYTEArrayVector solder_keys(solder_num_commit_keys, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(solder_keys.GetArray(), solder_keys.size);

  if (!commit_rec.BatchDecommit(solder_keys_share.GetArray(), solder_num_commit_keys, solder_keys.GetArray())) {
    std::cout << "Abort, soldering decommit failed!" << std::endl;
    throw std::runtime_error("Abort, soldering decommit failed!");
  }

  //Apply solderings
  for (int i = 0; i < exec_num_buckets; ++i) {
    curr_head_circuit = i * bucket_size;
    //Copy the head aux info for writing to disc
    std::copy(exec_permuted_aux_info[curr_head_circuit], exec_permuted_aux_info[curr_head_circuit] + eval_aux_size, exec_write_head_auxdata[i]); //Must be + eval_aux_size here!

    //Copy the head soldering info for writing to disc
    std::copy(EvalGarbledCircuit::inp_soldering(circuit, exec_permuted_aux_info[curr_head_circuit]),
              EvalGarbledCircuit::inp_soldering(circuit, exec_permuted_aux_info[curr_head_circuit]) + solderings_size, exec_write_solderings[curr_head_circuit]);

    for (int l = 1; l < bucket_size; ++l) {
      curr_circuit = curr_head_circuit + l;
      curr_solder_read_pos = curr_circuit - (i + 1);

      //Add delta soldering
      std::copy(solder_keys[solder_deltas_idx + curr_solder_read_pos],
                solder_keys[solder_deltas_idx + curr_solder_read_pos + 1],
                EvalGarbledCircuit::delta_soldering(circuit, exec_permuted_aux_info[curr_circuit]));

      for (int j = 0; j < circuit.num_inp_wires; ++j) {
        //Add input solderings
        std::copy(solder_keys[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j],
                  solder_keys[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j + 1],
                  EvalGarbledCircuit::inp_soldering(circuit, exec_permuted_aux_info[curr_circuit], j));
      }

      for (int j = 0; j < circuit.num_out_wires; ++j) {
        XOR_128(EvalGarbledCircuit::out_soldering(circuit, exec_permuted_aux_info[curr_circuit], j),
                solder_keys[solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j]);
      }

      //Copy the head soldering info for writing to disc
      std::copy(EvalGarbledCircuit::inp_soldering(circuit, exec_permuted_aux_info[curr_circuit]),
                EvalGarbledCircuit::inp_soldering(circuit, exec_permuted_aux_info[curr_circuit]) + solderings_size, exec_write_solderings[curr_circuit]);
    }
  }

  //////////////////////////////Write to Disc/////////////////////////////////

  uint64_t exec_tables_write_pos = exec_received_garbled_tables.size * exec_common_tools.exec_id;
  uint64_t exec_solderings_write_pos = exec_write_solderings.size * exec_common_tools.exec_id;
  uint64_t exec_auxdata_write_pos = exec_write_head_auxdata.size * exec_common_tools.exec_id;

  persistent_storage.WriteBuckets(component_type, TABLES, exec_buckets_from, exec_num_buckets, exec_received_garbled_tables.GetArray(), exec_tables_write_pos, exec_received_garbled_tables.size, bucket_size);
  persistent_storage.WriteBuckets(component_type, SOLDERINGS, exec_buckets_from, exec_num_buckets, exec_write_solderings.GetArray(), exec_solderings_write_pos, exec_write_solderings.size, bucket_size);
  persistent_storage.WriteBuckets(component_type, AUXDATA, exec_buckets_from, exec_num_buckets, exec_write_head_auxdata.GetArray(), exec_auxdata_write_pos, exec_write_head_auxdata.size, bucket_size);
}

void FrigateDuploEvaluator::CommitAuthAndCutAndChoose(CommonTools & exec_common_tools, uint32_t exec_num_auths, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_auths_from, uint32_t exec_eval_auths_to, std::vector<BYTEArrayVector>& eval_auths, BYTEArrayVector & aux_auth_data, std::vector<uint32_t>& eval_auths_ids, uint8_t aux_auth_delta_data[], std::tuple<std::mutex&, std::condition_variable&, bool&>& delta_signal) {

  CommitReceiver commit_rec(exec_common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());

  //If this is exec_id == 0 we produce one delta commitment.
  uint32_t num_commit_keys;
  if (exec_common_tools.exec_id == 0) {
    num_commit_keys = exec_num_auths + 1;
  } else {
    num_commit_keys = exec_num_auths;
  }

  BYTEArrayVector commit_keys_share(num_commit_keys, CODEWORD_BYTES);

  if (!commit_rec.Commit(num_commit_keys, commit_keys_share, exec_prg_counter, num_commit_keys)) {
    std::cout << "Abort, key commit failed!" << std::endl;;
    throw std::runtime_error("Abort, key commit failed!");
  }

  //If not execution 0, wait until execution 0 has put the delta commitment into aux_auth_delta_data
  std::condition_variable& delta_updated_cond_val = std::get<1>(delta_signal);
  bool& delta_updated = std::get<2>(delta_signal);

  if (exec_common_tools.exec_id == 0) {
    std::copy(commit_keys_share[num_commit_keys - 1], commit_keys_share[num_commit_keys], aux_auth_delta_data);
    delta_updated = true;
    delta_updated_cond_val.notify_all();
  } else {
    std::mutex& delta_updated_mutex = std::get<0>(delta_signal);
    unique_lock<mutex> lock(delta_updated_mutex);
    while (!delta_updated) {
      delta_updated_cond_val.wait(lock);
    }
  }

  //Index offsets, only used for cut-and-choose. When written to disc wire authenticators are written 32 bytes at a time, so H_0 and H_1 are always next to each other.
  uint32_t H_0_idx = 0;
  uint32_t H_1_idx = exec_num_auths;

  BYTEArrayVector auths(2 * exec_num_auths, CSEC_BYTES);

  exec_common_tools.chan.ReceiveBlocking(auths.GetArray(), auths.size);

  //Sample and send challenge seed
  uint8_t cnc_seed[CSEC_BYTES];
  exec_common_tools.rnd.GenRnd(cnc_seed, CSEC_BYTES);
  exec_common_tools.chan.Send(cnc_seed, CSEC_BYTES);

  //Select challenge circuits based on cnc_seed
  uint32_t num_bytes_exec_num_auths = BITS_TO_BYTES(exec_num_auths);
  std::vector<uint8_t> cnc_check_auths(num_bytes_exec_num_auths);

  PRNG cnc_rand;
  cnc_rand.SetSeed(cnc_seed);

  WeightedRandomString(cnc_check_auths.data(), check_factor, num_bytes_exec_num_auths, cnc_rand, negate_check_factor);

  int cnc_num_auths = countSetBits(cnc_check_auths.data(), 0, exec_num_auths - 1);
  uint32_t num_bytes_checked_circuits = BITS_TO_BYTES(cnc_num_auths);

  std::vector<uint8_t> cnc_check_inputs(num_bytes_checked_circuits);
  cnc_rand.GenRnd(cnc_check_inputs.data(), cnc_check_inputs.size());

  //Array for holding the decommit shares of the decommited keys
  BYTEArrayVector cnc_keys_share(cnc_num_auths, CODEWORD_BYTES);

  uint32_t current_check_auth_idx = 0;
  uint32_t current_eval_auth_idx = exec_eval_auths_from;
  uint32_t global_auth_idx;
  bool completed_eval_copy = false;
  for (int i = 0; i < exec_num_auths; ++i) {
    if (GetBit(i, cnc_check_auths.data())) { //Checked auths

      //Add key shares
      std::copy(commit_keys_share[i], commit_keys_share[(i + 1)], cnc_keys_share[current_check_auth_idx]);

      if (GetBit(current_check_auth_idx, cnc_check_inputs.data())) {
        XOR_CodeWords(cnc_keys_share[current_check_auth_idx], aux_auth_delta_data);
      }

      ++current_check_auth_idx;
    } else if (current_eval_auth_idx < exec_eval_auths_to) {

      //Store id info
      global_auth_idx = exec_eval_auths_from + i;
      eval_auths_ids[current_eval_auth_idx] = global_auth_idx;

      //Copy key info
      std::copy(commit_keys_share[i], commit_keys_share[(i + 1)], aux_auth_data[current_eval_auth_idx]);

      //Store eval authenticator
      std::copy(auths[H_0_idx + i], auths[H_0_idx + i + 1], eval_auths[current_eval_auth_idx][0]);
      std::copy(auths[H_1_idx + i], auths[H_1_idx + i + 1], eval_auths[current_eval_auth_idx][1]);

      ++current_eval_auth_idx;
    } else {
      completed_eval_copy = true;
    }
  }

  if (!completed_eval_copy) {
    std::cout << "Problem. Not enough eval auths! Params should be set so this never occurs" << std::endl;
  }

  BYTEArrayVector cnc_keys(cnc_num_auths, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(cnc_keys.GetArray(), cnc_keys.size);

  if (!commit_rec.BatchDecommit(cnc_keys_share.GetArray(), cnc_num_auths, cnc_keys.GetArray())) {
    std::cout << "Abort, auth cut-and-choose decommit failed!" << std::endl;
    throw std::runtime_error("Abort, auth cut-and-choose decommit failed!");
  }

  GarblingHandler gh;
  current_check_auth_idx = 0;
  bool success = true;
  for (int i = 0; i < exec_num_auths; ++i) {
    if (GetBit(i, cnc_check_auths.data())) { //Checked auths
      global_auth_idx = exec_eval_auths_from + i;
      if (!VerifyAuth(cnc_keys[current_check_auth_idx], auths[H_0_idx + i], auths[H_1_idx + i], global_auth_idx, gh.key_schedule)) {
        success = false;
      }
      ++current_check_auth_idx;
    }
  }
  if (!success) {
    std::cout << "Abort, auth cut-and-choose eval failed!" << std::endl;
    throw std::runtime_error("Abort, auth cut-and-choose eval failed!");
  }
}

void FrigateDuploEvaluator::BucketAllAuths(std::vector<std::tuple<std::string, Circuit, uint64_t>>& circuit_info, CommonTools & exec_common_tools, uint32_t auth_size, std::vector<uint32_t>& permuted_eval_ids_inv, std::vector<int>& session_circuit_buckets_from, std::vector<int>& session_circuit_buckets_to, std::vector<BYTEArrayVector>& eval_auths, BYTEArrayVector & aux_auth_data, std::vector<uint32_t>& eval_auths_ids, uint8_t aux_auth_delta_data[]) {

  uint32_t num_sessions = session_circuit_buckets_from.size();

  std::vector<uint32_t> auth_session_start_pos(1, 0); // first starts at 0

  uint32_t total_num_solderings = 0;
  for (int l = 0; l < num_sessions; ++l) {
    Circuit& session_circuit = std::get<1>(circuit_info[l]);
    uint32_t session_num_circuit_buckets = std::get<2>(circuit_info[l]);
    uint32_t exec_session_num_circuit_buckets = session_circuit_buckets_to[l] - session_circuit_buckets_from[l];

    total_num_solderings += exec_session_num_circuit_buckets * (auth_size * session_circuit.num_out_wires + 1);

    //Compute "global" read offset for authenticators.
    uint32_t curr_auth_session_start_pos = auth_session_start_pos[l] + session_num_circuit_buckets * auth_size * session_circuit.num_out_wires;
    auth_session_start_pos.push_back(curr_auth_session_start_pos);
  }

  //For decomitting later on
  BYTEArrayVector solder_keys_share(total_num_solderings, CODEWORD_BYTES);
  BYTEArrayVector solder_keys(total_num_solderings, CSEC_BYTES);

  uint32_t curr_solder_write_pos = 0;
  for (int l = 0; l < num_sessions; ++l) {

    std::string component_type = std::get<0>(circuit_info[l]);
    Circuit& session_circuit = std::get<1>(circuit_info[l]);

    uint32_t exec_session_num_circuit_buckets = session_circuit_buckets_to[l] - session_circuit_buckets_from[l];

    //Read all session circuit info
    BYTEArrayVector curr_session_aux_info;
    persistent_storage.ReadBuckets(component_type, AUXDATA, session_circuit_buckets_from[l], exec_session_num_circuit_buckets, curr_session_aux_info);

    //For each bucket in the session
    for (int i = 0; i < exec_session_num_circuit_buckets; ++i) {
      uint32_t curr_session_bucket_idx = i + session_circuit_buckets_from[l];

      //Copy Delta soldering
      std::copy(EvalGarbledCircuit::delta_share(session_circuit, curr_session_aux_info[i]),
                EvalGarbledCircuit::delta_share(session_circuit, curr_session_aux_info[i] + CODEWORD_BYTES),
                solder_keys_share[curr_solder_write_pos]);
      XOR_CodeWords(solder_keys_share[curr_solder_write_pos], aux_auth_delta_data);

      ++curr_solder_write_pos;

      //Copy all bucket_size*session_circuit.num_out_wires solderings
      for (int j = 0; j < session_circuit.num_out_wires; ++j) {
        for (int a = 0; a < auth_size; ++a) {
          uint32_t perm_auth_idx = permuted_eval_ids_inv[auth_session_start_pos[l] + (curr_session_bucket_idx * session_circuit.num_out_wires + j) * auth_size + a];
          uint8_t* current_aux_auth_data = aux_auth_data[perm_auth_idx];

          std::copy(EvalGarbledCircuit::out_key_share(session_circuit, curr_session_aux_info[i], j),
                    EvalGarbledCircuit::out_key_share(session_circuit, curr_session_aux_info[i], j + 1),
                    solder_keys_share[curr_solder_write_pos]);
          XOR_CodeWords(solder_keys_share[curr_solder_write_pos], current_aux_auth_data);

          ++curr_solder_write_pos;
        }
      }
    }
  }

  CommitReceiver commit_rec(exec_common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());

  exec_common_tools.chan.ReceiveBlocking(solder_keys.GetArray(), solder_keys.size);

  if (!commit_rec.BatchDecommit(solder_keys_share.GetArray(), total_num_solderings, solder_keys.GetArray())) {
    std::cout << "Abort, auth soldering decommit failed!" << std::endl;
    throw std::runtime_error("Abort, auth soldering decommit failed!");
  }

  //Write solderings to disc
  uint32_t curr_solder_read_pos = 0;
  for (int l = 0; l < num_sessions; ++l) {

    std::string session_component_type = std::get<0>(circuit_info[l]);
    Circuit& session_circuit = std::get<1>(circuit_info[l]);
    uint64_t session_num_buckets = std::get<2>(circuit_info[l]);

    uint32_t exec_session_num_circuit_buckets = session_circuit_buckets_to[l] - session_circuit_buckets_from[l];

    uint32_t exec_session_num_auth_buckets = exec_session_num_circuit_buckets * session_circuit.num_out_wires;
    uint32_t exec_session_auth_bucket_from = session_circuit_buckets_from[l] * session_circuit.num_out_wires;

    BYTEArrayVector exec_session_auths(exec_session_num_auth_buckets * auth_size, 2 * CSEC_BYTES);
    BYTEArrayVector exec_session_auths_solderings(exec_session_num_auth_buckets * auth_size, CSEC_BYTES);
    BYTEArrayVector exec_session_delta_solder(exec_session_num_circuit_buckets, CSEC_BYTES);
    BYTEArrayVector exec_session_global_ids(exec_session_num_auth_buckets * auth_size, sizeof(uint32_t));

    for (int i = 0; i < exec_session_num_circuit_buckets; ++i) {
      uint32_t curr_session_bucket_idx = i + session_circuit_buckets_from[l];

      std::copy(solder_keys[curr_solder_read_pos], solder_keys[curr_solder_read_pos + 1], exec_session_delta_solder[i]);

      ++curr_solder_read_pos;

      //Copy all bucket_size*session_circuit.num_out_wires solderings
      for (int j = 0; j < session_circuit.num_out_wires; ++j) {
        for (int a = 0; a < auth_size; ++a) {

          uint32_t perm_auth_idx = permuted_eval_ids_inv[auth_session_start_pos[l] + (curr_session_bucket_idx * session_circuit.num_out_wires + j) * auth_size + a];

          //Copy auths
          std::copy(
            eval_auths[perm_auth_idx][0],
            eval_auths[perm_auth_idx][0] + CSEC_BYTES,
            exec_session_auths[(i * session_circuit.num_out_wires + j) * auth_size + a]);

          std::copy(
            eval_auths[perm_auth_idx][1],
            eval_auths[perm_auth_idx][1] + CSEC_BYTES,
            exec_session_auths[(i * session_circuit.num_out_wires + j) * auth_size + a] + CSEC_BYTES);

          //Copy auth solderings
          std::copy(solder_keys[curr_solder_read_pos],
                    solder_keys[curr_solder_read_pos + 1],
                    exec_session_auths_solderings[(i * session_circuit.num_out_wires + j) * auth_size + a]);

          //Copy global idx
          std::copy((uint8_t*) & (eval_auths_ids[perm_auth_idx]),
                    (uint8_t*) & (eval_auths_ids[perm_auth_idx]) + sizeof(uint32_t),
                    exec_session_global_ids[(i * session_circuit.num_out_wires + j) * auth_size + a]);

          ++curr_solder_read_pos;
        }
      }
    }

    uint64_t exec_auths_write_pos = exec_session_auths.size * exec_common_tools.exec_id;
    uint64_t exec_auths_solderings_write_pos = exec_session_auths_solderings.size * exec_common_tools.exec_id;
    uint64_t exec_auths_deltas_write_pos = exec_session_delta_solder.size * exec_common_tools.exec_id;
    uint64_t exec_auths_ids_write_pos = exec_session_global_ids.size * exec_common_tools.exec_id;

    //Write auths
    persistent_storage.WriteBuckets(session_component_type, AUTHS, exec_session_auth_bucket_from, exec_session_num_auth_buckets, exec_session_auths.GetArray(), exec_auths_write_pos, exec_session_auths.size, auth_size);

    //Write auth solderings
    persistent_storage.WriteBuckets(session_component_type, AUTHS_SOLDERINGS, exec_session_auth_bucket_from, exec_session_num_auth_buckets, exec_session_auths_solderings.GetArray(), exec_auths_solderings_write_pos, exec_session_auths_solderings.size, auth_size);

    //Write delta solderings
    persistent_storage.WriteBuckets(session_component_type, AUTHS_DELTA_SOLDERINGS, session_circuit_buckets_from[l], exec_session_num_circuit_buckets, exec_session_delta_solder.GetArray(), exec_auths_deltas_write_pos, exec_session_delta_solder.size, 1);

    //Write global auth ids
    persistent_storage.WriteBuckets(session_component_type, AUTHS_IDS, exec_session_auth_bucket_from, exec_session_num_auth_buckets, exec_session_global_ids.GetArray(), exec_auths_ids_write_pos, exec_session_global_ids.size, auth_size);
  }
}

void FrigateDuploEvaluator::PreprocessInputs(CommonTools& inp_common_tools, std::vector<std::pair<std::string, uint32_t>>& input_components) {

  uint32_t num_components = input_components.size();
  uint32_t num_total_eval_inputs = 0;
  for (int i = 0; i < num_components; ++i) {
    std::string component_name = std::get<0>(input_components[i]);
    uint32_t component_num = std::get<1>(input_components[i]);
    Circuit& circuit = string_to_circuit_map[component_name];

    num_total_eval_inputs += circuit.num_eval_inp_wires;
  }

  if (num_total_eval_inputs < 1) {
    return;
  }

  auto preprocess_inputs_begin = GET_TIME();

  //Run OTX
  uint32_t num_ots = num_total_eval_inputs + SSEC;
  BYTEArrayVector input_masks(num_ots, CSEC_BYTES);
  BYTEArrayVector input_masks_choices(BITS_TO_BYTES(num_ots), 1);
  ot_rec.Receive(num_ots, input_masks.GetArray(), input_masks_choices.GetArray());

  //Run Random Commit
  uint32_t num_commits = num_ots + 1;
  BYTEArrayVector commit_keys_share(num_commits, CODEWORD_BYTES);

  CommitReceiver commit_rec(inp_common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());
  uint32_t prg_counter = 0;
  commit_rec.Commit(num_commits, commit_keys_share, prg_counter);

  //Run chosen commit
  BYTEArrayVector input_mask_corrections(num_commits, CSEC_BYTES);
  inp_common_tools.chan.ReceiveBlocking(input_mask_corrections.GetArray(), input_mask_corrections.size);

  //////////////////////////////////////CNC////////////////////////////////////

  //Send own values to sender
  std::vector<uint8_t> cnc_ot_values(SSEC * CSEC_BYTES + SSEC_BYTES);
  uint8_t* ot_delta_cnc_choices = cnc_ot_values.data() + SSEC * CSEC_BYTES;

  std::copy(input_masks[num_total_eval_inputs], input_masks[num_ots], cnc_ot_values.data());

  for (int i = 0; i < SSEC; ++i) {
    if (GetBit((num_total_eval_inputs + i), input_masks_choices.GetArray())) {
      SetBit(i, 1, ot_delta_cnc_choices);
    } else {
      SetBit(i, 0, ot_delta_cnc_choices);
    }
  }
  inp_common_tools.chan.Send(cnc_ot_values.data(),  SSEC * CSEC_BYTES + SSEC_BYTES);

  //Compute decommit shares
  BYTEArrayVector chosen_decommit_shares(SSEC, CODEWORD_BYTES);
  for (int i = 0; i < SSEC; ++i) {
    std::copy(commit_keys_share[num_total_eval_inputs + i], commit_keys_share[num_total_eval_inputs + i + 1], chosen_decommit_shares[i]);

    if (GetBit(i, ot_delta_cnc_choices)) {
      XOR_CodeWords(chosen_decommit_shares[i], commit_keys_share[num_ots]);
    }
  }

  //Receive decommits
  BYTEArrayVector chosen_decommit_shares0(SSEC, CODEWORD_BYTES);
  BYTEArrayVector chosen_decommit_shares1(SSEC, CODEWORD_BYTES);
  inp_common_tools.chan.ReceiveBlocking(chosen_decommit_shares0.GetArray(), chosen_decommit_shares0.size);
  inp_common_tools.chan.ReceiveBlocking(chosen_decommit_shares1.GetArray(), chosen_decommit_shares1.size);

  //Check the decommits
  BYTEArrayVector decomitted_values(SSEC, CSEC_BYTES);
  if (!VerifyDecommits(chosen_decommit_shares0.GetArray(), chosen_decommit_shares1.GetArray(), chosen_decommit_shares.GetArray(), decomitted_values.GetArray(), commit_seed_choices.GetArray(), commit_rec.code.get(), SSEC)) {
    std::cout << "Sender decommit fail in OT CNC!" << std::endl;
  }

  //Apply the corrections
  uint8_t chosen_decommit_val[CSEC_BYTES];
  for (int i = 0; i < SSEC; ++i) {
    XOR_128(chosen_decommit_val, decomitted_values[i], input_mask_corrections[num_total_eval_inputs + i]);
    if (GetBit((num_total_eval_inputs + i), input_masks_choices.GetArray())) {
      XOR_128(chosen_decommit_val, input_mask_corrections[num_ots]);
    }

    //Check if they match known value
    if (!std::equal(input_masks[num_total_eval_inputs + i], input_masks[num_total_eval_inputs + i + 1], chosen_decommit_val)) {
      std::cout << "Sender cheating in OT CNC. Decomitted to wrong values. Did not commit to Delta!" << std::endl;
    }
  }

  curr_num_ready_inputs = num_total_eval_inputs;

  BYTEArrayVector shares(num_total_eval_inputs, CODEWORD_BYTES + 1);
  for (int i = 0; i < num_total_eval_inputs; ++i) {
    std::copy(commit_keys_share[i], commit_keys_share[i + 1], shares[i]);
    if (GetBit (i, input_masks_choices.GetArray())) {
      *(shares[i] + CODEWORD_BYTES) = 1;
    } //else it's zero

    XOR_128(input_mask_corrections[i], input_masks[i]); // turns input_mask_corrections[i] into committed value
  }

  persistent_storage.PrepareFile(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_AUXDATA, num_total_eval_inputs * (CODEWORD_BYTES + 1));
  persistent_storage.PrepareFile(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_DELTA_AUXDATA, CODEWORD_BYTES);
  persistent_storage.PrepareFile(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_CORRECTIONS, num_total_eval_inputs * CSEC_BYTES);
  persistent_storage.PrepareFile(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_DELTA_CORRECTION, CSEC_BYTES);

  persistent_storage.WriteBuckets(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_AUXDATA, 0, num_total_eval_inputs, shares.GetArray(), 0, num_total_eval_inputs * (CODEWORD_BYTES + 1), 1);

  persistent_storage.WriteBuckets(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_DELTA_AUXDATA, 0, 1, commit_keys_share[num_ots], 0, CODEWORD_BYTES, 1);

  persistent_storage.WriteBuckets(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_CORRECTIONS, 0, num_total_eval_inputs, input_mask_corrections.GetArray(), 0, num_total_eval_inputs * CSEC_BYTES, 1);
  persistent_storage.WriteBuckets(EVAL_PREPROCESS_PREFIX, INPUT_MASKS_DELTA_CORRECTION, 0, 1, input_mask_corrections[num_ots], 0, CSEC_BYTES, 1);

  uint8_t dummy;
  inp_common_tools.chan.Send(&dummy, 1);

  auto preprocess_inputs_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(preprocess_inputs_begin, preprocess_inputs_end, num_components, "PreprocessInputs");
#endif
}

void FrigateDuploEvaluator::DecommitEvalPermBits(CommonTools& inp_common_tools, std::vector<std::pair<std::string, uint32_t>>& input_components) {

  auto attach_input_components_begin = GET_TIME();

  uint32_t num_components = input_components.size();

  //Read inp perm bits corresponding to components
  std::vector<uint32_t> eval_inp_sizes, const_inp_sizes, eval_inp_pos;
  uint32_t num_total_eval_inputs = 0;
  for (int i = 0; i < num_components; ++i) {
    std::string component_name = std::get<0>(input_components[i]);
    uint32_t component_num = std::get<1>(input_components[i]);
    Circuit& circuit = string_to_circuit_map[component_name];

    eval_inp_pos.emplace_back(num_total_eval_inputs);
    num_total_eval_inputs += circuit.num_eval_inp_wires;

    eval_inp_sizes.emplace_back(circuit.num_eval_inp_wires);
    const_inp_sizes.emplace_back(circuit.num_const_inp_wires);
  }

  if (num_total_eval_inputs < 1) {
    return;
  }

  BYTEArrayVector b_share(num_total_eval_inputs, BIT_CODEWORD_BYTES);

  for (int i = 0; i < num_components; ++i) {
    std::string component_name = std::get<0>(input_components[i]);
    uint32_t component_num = std::get<1>(input_components[i]);
    Circuit& circuit = string_to_circuit_map[component_name];

    BYTEArrayVector component_aux_data;
    persistent_storage.ReadBuckets(component_name, AUXDATA, component_num, 1, component_aux_data);

    for (int j = 0; j < eval_inp_sizes[i]; ++j) {
      std::copy(EvalGarbledCircuit::inp_bit_share(circuit, component_aux_data[0], const_inp_sizes[i] + j),
                EvalGarbledCircuit::inp_bit_share(circuit, component_aux_data[0], const_inp_sizes[i] + j + 1),
                b_share[eval_inp_pos[i] + j]);
    }
  }

  BYTEArrayVector b(BITS_TO_BYTES(num_total_eval_inputs), 1);
  inp_common_tools.chan.ReceiveBlocking(b.GetArray(), b.size);

  BitCommitReceiver bit_commit_rec(inp_common_tools, commit_seed_OTs[CODEWORD_BITS], commit_seed_choices[CODEWORD_BYTES]);
  if (!bit_commit_rec.BatchDecommit(b_share.GetArray(), num_total_eval_inputs, b.GetArray())) {
    std::cout << "Abort, input perm bit decommit failed!" << std::endl;
    throw std::runtime_error("Abort, input perm bit decommit failed!");
  }

  std::vector<uint8_t*> b_vec(num_components);
  uint32_t inc_pos = 0;
  for (int i = 0; i < num_components; ++i) {
    b_vec[i] = b.GetArray() + inc_pos;
    inc_pos += BITS_TO_BYTES(eval_inp_sizes[i]);
  }

  persistent_storage.PrepareFile(EVAL_PREPROCESS_PREFIX, INPUT_PERM_BITS, BITS_TO_BYTES(num_total_eval_inputs));

  for (int i = 0; i < num_components; ++i) {
    perm_bits_pos_map.emplace(std::make_tuple(std::get<0>(input_components[i]), std::get<1>(input_components[i])), i);

    persistent_storage.WriteBuckets(EVAL_PREPROCESS_PREFIX, INPUT_PERM_BITS, i, 1, b_vec[i], BITS_TO_BYTES(eval_inp_pos[i]), BITS_TO_BYTES(eval_inp_sizes[i]), 1);
  }

  uint8_t dummy;
  inp_common_tools.chan.Send(&dummy, 1);

  auto attach_input_components_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(attach_input_components_begin, attach_input_components_end, num_components, "AttachInputComponents");
#endif
}


void FrigateDuploEvaluator::EvalBucketsParallel(std::vector<std::pair<std::string, uint32_t>>& components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& input_keys, std::vector<BYTEArrayVector>& output_keys) {

  uint32_t num_components = components_to - components_from;

  GarblingHandler gh;
  std::mutex cout_mutex;
  for (uint64_t l = 0; l < num_components; ++l) {
    uint32_t curr_component = components_from + l;
    std::string component_name = std::get<0>(components[curr_component]);
    uint32_t component_num = std::get<1>(components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];

    uint32_t garbled_table_size = GarbledCircuit::TotalTableSize(circuit);
    uint32_t solderings_size = EvalGarbledCircuit::SolderingsSize(circuit);

    BYTEArrayVector read_buckets;;
    BYTEArrayVector read_solderings;;

    // auto io_time_begin = GET_TIME();
    persistent_storage.ReadBuckets(component_name, TABLES, component_num, 1, read_buckets);
    persistent_storage.ReadBuckets(component_name, SOLDERINGS, component_num, 1, read_solderings);
    // auto io_time_end = GET_TIME();
    // BYTEArrayVector read_buckets = BYTEArrayVector(4, garbled_table_size);
    // BYTEArrayVector read_solderings = BYTEArrayVector(4, solderings_size);

// #ifdef DUPLO_PRINT
    // std::cout << "bucket " << l << " ";
    // PRINT_TIME(io_time_end, io_time_begin, "took io time");
// #endif

    uint32_t bucket_size = read_buckets.entry_size / garbled_table_size;
    // bucket_sizes[l] = bucket_size;

    //TODO: Read the input buckets, and check the bucket input wires using these! Cannot be done before input bucket code has been written

    std::vector<BYTEArrayVector> cand_outputs(bucket_size, BYTEArrayVector(circuit.num_out_wires, CSEC_BYTES));
    std::vector<std::future<void>> futures;
    for (uint64_t i = 0; i < bucket_size; ++i) {

      futures.emplace_back(std::async(std::launch::async, [this, &read_buckets, &read_solderings, &gh, &input_keys, &components, &cand_outputs, l, curr_component, i, garbled_table_size, solderings_size, &cout_mutex]() {

        uint8_t* curr_garbled_tables = read_buckets.GetArray() + i * garbled_table_size;
        uint8_t* curr_solderings = read_solderings.GetArray() + i * solderings_size;

        Circuit& circuit = string_to_circuit_map[std::get<0>(components[curr_component])];
        gh.EvalGarbledCircuitSolderings(input_keys[l].GetArray(), circuit, curr_garbled_tables, curr_solderings, cand_outputs[i].GetArray());
      }));
    }

    for (std::future<void>& f : futures) {
      f.wait();
    }

    //Check all non-head circuits towards the head circuits' output
    bool success = true;
    for (int i = 1; i < bucket_size; ++i) { //We check towards head circuit
      if (!std::equal(cand_outputs[0][0], cand_outputs[0][circuit.num_out_wires], cand_outputs[i].GetArray())) {
        success = false;
      }
    }

    if (success) {
      std::copy(cand_outputs[0][0], cand_outputs[0][circuit.num_out_wires], output_keys[curr_component].GetArray());
    } else {
      std::cout << "Problem! Bucket " << l << " doesn't output the same!" << std::endl;
      //Error handling, evaluate authenticators, etc etc
    }
  }
}

void FrigateDuploEvaluator::EvalBucketsSerial(std::vector<std::pair<std::string, uint32_t>>& components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& input_keys, std::vector<BYTEArrayVector>& output_keys) {

  uint32_t num_components = components_to - components_from;

  GarblingHandler gh;
  for (int l = 0; l < num_components; ++l) {
    uint32_t curr_component = components_from + l;

    std::string component_name = std::get<0>(components[curr_component]);
    uint32_t component_num = std::get<1>(components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];

    uint32_t garbled_table_size = GarbledCircuit::TotalTableSize(circuit);
    uint32_t solderings_size = EvalGarbledCircuit::SolderingsSize(circuit);

    BYTEArrayVector read_bucket;
    BYTEArrayVector read_solderings;
    // auto io_time_begin = GET_TIME();
    persistent_storage.ReadBuckets(component_name, TABLES, component_num, 1, read_bucket);
    persistent_storage.ReadBuckets(component_name, SOLDERINGS, component_num, 1, read_solderings);

    // auto io_time_end = GET_TIME();

    // BYTEArrayVector read_bucket(4, garbled_table_size);
    // BYTEArrayVector read_solderings(4, solderings_size);

// #ifdef DUPLO_PRINT
    // std::cout << "bucket " << l << " ";
    // PRINT_TIME(io_time_end, io_time_begin, "took io time");
// #endif

    uint32_t bucket_size = read_bucket.entry_size / garbled_table_size;

    bool success = true;
    std::vector<BYTEArrayVector> cand_outputs(bucket_size, BYTEArrayVector(circuit.num_out_wires, CSEC_BYTES));
    for (int i = 0; i < bucket_size; ++i) {

      uint8_t* curr_solderings = read_solderings.GetArray() + i * solderings_size;
      uint8_t* curr_garbled_tables = read_bucket.GetArray() + i * garbled_table_size;

      gh.EvalGarbledCircuitSolderings(input_keys[l].GetArray(), circuit, curr_garbled_tables, curr_solderings, cand_outputs[i].GetArray());

      if ( i != 0) {
        if (!std::equal(cand_outputs[0][0], cand_outputs[0][circuit.num_out_wires], cand_outputs[i].GetArray())) {
          success = false;
        }
      }
    }
    if (success) {
      std::copy(cand_outputs[0][0], cand_outputs[0][circuit.num_out_wires], output_keys[curr_component].GetArray());
    } else {
      //Error handling, evaluate authenticators, etc etc
      std::cout << "Problem! Bucket " << l << " doesn't output the same!" << std::endl;
    }
  }
}