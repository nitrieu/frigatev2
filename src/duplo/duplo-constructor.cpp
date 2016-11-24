#include "duplo/duplo-constructor.h"

DuploConstructor::DuploConstructor(CommonTools& common_tools, uint32_t num_max_parallel_execs) :
  Duplo(common_tools, num_max_parallel_execs),
  ot_snd(common_tools, true),
  commit_seed_OTs0(NUM_COMMIT_SEED_OT, CSEC_BYTES),
  commit_seed_OTs1(NUM_COMMIT_SEED_OT, CSEC_BYTES)  {

}

void DuploConstructor::Setup() {

  ot_snd.InitOTSender();

  //OTX for commitment seeds
  uint8_t delta[CSEC_BYTES] = {0};

  ot_snd.Send(NUM_COMMIT_SEED_OT, commit_seed_OTs0.GetArray(), delta);

  //Requires computing commit_seed_OTs0 \xor delta and then hashing both values into a rot to remove the correlation
  for (int i = 0; i < NUM_COMMIT_SEED_OT; ++i) {
    XOR_128(commit_seed_OTs1[i], commit_seed_OTs0[i], delta);

    common_tools.crypt.hash(commit_seed_OTs0[i], CSEC_BYTES, commit_seed_OTs0[i], CSEC_BYTES);
    common_tools.crypt.hash(commit_seed_OTs1[i], CSEC_BYTES, commit_seed_OTs1[i], CSEC_BYTES);
  }
}

void DuploConstructor::PreprocessComponentType(std::string component_type, Circuit& circuit, uint32_t num_buckets, uint32_t num_parallel_execs, BucketType bucket_type) {

  if (string_to_circuit_map.find(component_type) != string_to_circuit_map.end()) {
    std::cout << component_type << " already preprocessed. Current implementation only supports one preprocess call per component_type." << std::endl;

    return;
  }

  string_to_circuit_map.emplace(component_type, circuit);
  num_buckets = PAD_TO_MULTIPLE(num_buckets, num_parallel_execs);

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

  PrintTimePerBucket(t_param_start, t_param_end, num_buckets, "FindSingleParam");

  //For printing
  double cnc_check_prob;
  if (negate_check_factor) {
    cnc_check_prob = 1 - (1 / pow(2, check_factor));
  } else {
    cnc_check_prob = (1 / pow(2, check_factor));
  }

  std::cout << "bucket_size=" << bucket_size << ", " << "cnc_check_prob=" << cnc_check_prob << std::endl;
#endif

  auto component_commit_cnc_begin = GET_TIME();

  uint32_t num_eval_circuits = bucket_size * num_buckets;

  std::vector<std::future<void>> execs_finished(num_parallel_execs);

  std::vector<int> eval_circuits_from, eval_circuits_to, buckets_from, buckets_to;

  PartitionBufferFixedNum(eval_circuits_from, eval_circuits_to, num_parallel_execs, num_eval_circuits);
  PartitionBufferFixedNum(buckets_from, buckets_to, num_parallel_execs, num_buckets);

  std::vector<ConstGarbledCircuit> aux_garbled_circuits_data(num_eval_circuits, ConstGarbledCircuit(circuit, 0));

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    uint64_t exec_prg_counter = curr_prg_counter;
    curr_prg_counter += FIXED_PRG_INC_NUMBER;

    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &aux_garbled_circuits_data, &eval_circuits_from, &eval_circuits_to, exec_id, &circuit, exec_prg_counter, check_factor, negate_check_factor] (int id) {

      uint32_t exec_num_buckets = eval_circuits_to[exec_id] - eval_circuits_from[exec_id];

      float slack_val, repl_factor;
      ComputeCheckFraction(check_factor, exec_num_buckets, slack_val, repl_factor, negate_check_factor);

      uint32_t exec_num_total_circuits = ceil(repl_factor * exec_num_buckets);

      CommitGarbleAndCutAndChoose(exec_common_tools, circuit, exec_num_total_circuits, exec_prg_counter, check_factor, negate_check_factor, eval_circuits_from[exec_id], eval_circuits_to[exec_id], aux_garbled_circuits_data);
    });
  }

  for (std::future<void>& r : execs_finished) {
    r.wait();
  }

  circuit_info.emplace_back(std::make_tuple(component_type, circuit, num_buckets));

  auto component_commit_cnc_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(component_commit_cnc_begin, component_commit_cnc_end, num_buckets, "ComponentCommitCNC");
#endif

  uint64_t auxdata_bytes = ConstGarbledCircuit::AuxDataSize(circuit) * num_buckets;

  persistent_storage.PrepareFile(component_type, AUXDATA, auxdata_bytes);

  uint8_t bucket_seed[CSEC_BYTES];
  common_tools.chan.ReceiveBlocking(bucket_seed, CSEC_BYTES);

  std::vector<uint32_t> permuted_eval_ids(num_eval_circuits);
  std::vector<uint32_t> permuted_eval_ids_inv(num_eval_circuits);
  std::iota(std::begin(permuted_eval_ids), std::end(permuted_eval_ids), 0);
  PermuteArray(permuted_eval_ids.data(), num_eval_circuits, bucket_seed);
  for (int i = 0; i < num_eval_circuits; ++i) {
    permuted_eval_ids_inv[permuted_eval_ids[i]] = i;
  }

  auto component_bucketing_begin = GET_TIME();

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {
    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &aux_garbled_circuits_data, &buckets_from, &buckets_to, exec_id, &circuit, bucket_size, &permuted_eval_ids_inv, &component_type] (int id) {

      BucketAndSendEvalCircuits(component_type, exec_common_tools, circuit, bucket_size, permuted_eval_ids_inv, buckets_from[exec_id], buckets_to[exec_id], aux_garbled_circuits_data);
    });
  }

  for (std::future<void>& r : execs_finished) {
    r.wait();
  }

  auto component_bucketing_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(component_bucketing_begin, component_bucketing_end, num_buckets, "ComponentBucketing");
#endif
}

void DuploConstructor::SolderGarbledComponents(std::string& res_component, ComposedCircuit& composed_circuit, uint32_t num_parallel_execs) {

  string_to_composed_circuit_map.emplace(res_component, composed_circuit);

  uint32_t num_inp_wire_components = composed_circuit.circuits.size() - composed_circuit.num_inp_circuits;

  std::vector<int> inp_wire_components_from, inp_wire_components_to;
  PartitionBufferFixedNum(inp_wire_components_from, inp_wire_components_to, num_parallel_execs, num_inp_wire_components);

  std::vector<std::future<void>> futures;
  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();
    futures.emplace_back(thread_pool.push([this, &exec_common_tools, &res_component, &composed_circuit, &inp_wire_components_from, &inp_wire_components_to, exec_id] (int id) {

      ComputeAndSendSolderings(exec_common_tools, res_component, composed_circuit, inp_wire_components_from[exec_id], inp_wire_components_to[exec_id]);
    }));
  }

  for (std::future<void>& f : futures) {
    f.wait();
  }
}

void DuploConstructor::EvalComposedComponents(std::string& res_component, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& const_output_keys, uint32_t num_parallel_execs) {

  ComposedCircuit& composed_circuit = string_to_composed_circuit_map[res_component];

  std::vector<std::pair<std::string, uint32_t>> input_components;
  for (int c = 0; c < composed_circuit.num_inp_circuits; ++c) {
    input_components.emplace_back(composed_circuit.circuits[c]);
  }
  std::vector<BYTEArrayVector> input_components_outputs(composed_circuit.num_inp_circuits);

  //false meaning we do not send back the keys in input_components_outputs during this call. This is because we only send back the final output keys
  EvalComponents(input_components, inputs, input_components_outputs, num_parallel_execs, false);

  BYTEArrayVector all_const_output_keys(GetNumOutWires(composed_circuit, CONST_OUT), CSEC_BYTES);
  common_tools.chan.ReceiveBlocking(all_const_output_keys.GetArray(), all_const_output_keys.size);

  uint32_t num_circuits = composed_circuit.circuits.size();
  uint32_t curr_out_pos = 0;
  for (int l = num_circuits - composed_circuit.num_out_circuits; l < num_circuits; ++l) {
    std::string component_name(std::get<0>(composed_circuit.circuits[l]));
    Circuit& circuit = string_to_circuit_map[component_name];

    const_output_keys.emplace_back(BYTEArrayVector(circuit.num_const_out_wires, CSEC_BYTES));

    uint32_t curr_idx = l - (num_circuits - composed_circuit.num_out_circuits);
    std::copy(all_const_output_keys[curr_out_pos], all_const_output_keys[curr_out_pos + circuit.num_const_out_wires], const_output_keys[curr_idx].GetArray());

    curr_out_pos += circuit.num_const_out_wires;
  }
}
void DuploConstructor::PrepareComponents(std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t num_parallel_execs) {

  //Find out how many input wires
  uint64_t num_total_const_inputs = 0;
  uint64_t num_total_eval_inputs = 0;
  for (int i = 0; i < input_components.size(); ++i) {
    std::string component_name = std::get<0>(input_components[i]);
    Circuit& circuit = string_to_circuit_map[component_name];
    num_total_const_inputs += circuit.num_const_inp_wires;
    num_total_eval_inputs += circuit.num_eval_inp_wires;
  }

  uint64_t num_total_inputs = num_total_const_inputs + num_total_eval_inputs;

  uint64_t num_circuit_buckets = 0;
  uint64_t num_circuit_auth_buckets = 0;
  for (std::tuple<std::string, Circuit, uint64_t>& c_info : circuit_info) {
    num_circuit_buckets += std::get<2>(c_info);
    num_circuit_auth_buckets += std::get<2>(c_info) * std::get<1>(c_info).num_out_wires;
  }

  if ((num_circuit_buckets % num_parallel_execs) != 0) {
    std::cout << "Bad number of auth parallel execs used! Need to be multiple of total garbled components" << std::endl;
    // throw std::runtime_error("Bad number of auth parallel execs used! Need to be multiple of total garbled components");
  }

  uint64_t num_total_auth_buckets = num_circuit_auth_buckets + num_total_inputs;

  std::vector<std::future<void>> execs_finished(num_parallel_execs);

  //Compute parameters
  long double check_factor;
  uint32_t auth_size;
  bool negate_check_factor;

  auto t_param_start = GET_TIME();
  FindBestMajorityParams(num_total_auth_buckets, auth_size, check_factor, negate_check_factor, 2); //We only catch a bad wire authenticator w. prob 1/2
  auto t_param_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(t_param_start, t_param_end, num_circuit_buckets, "FindMajParam");

  double cnc_check_prob;
  if (negate_check_factor) {
    cnc_check_prob = 1 - (1 / pow(2, check_factor));
  } else {
    cnc_check_prob = (1 / pow(2, check_factor));
  }

  std::cout << "auth_size=" << auth_size << ", " << "cnc_check_prob=" << cnc_check_prob << std::endl;
#endif

  auto prepare_eval_commit_cnc_begin = GET_TIME();

  std::vector<uint32_t> input_components_auth_start_pos;
  uint32_t curr_start_pos = num_circuit_auth_buckets * auth_size;
  for (int i = 0; i < input_components.size(); ++i) {
    std::string component_name = std::get<0>(input_components[i]);
    Circuit& circuit = string_to_circuit_map[component_name];
    input_components_auth_start_pos.emplace_back(curr_start_pos);
    curr_start_pos += circuit.num_inp_wires * auth_size;
  }

  uint32_t num_eval_auths = num_total_auth_buckets * auth_size;

  std::vector<int> eval_auths_from, eval_auths_to, input_components_from, input_components_to;
  PartitionBufferFixedNum(eval_auths_from, eval_auths_to, num_parallel_execs, num_eval_auths);
  PartitionBufferFixedNum(input_components_from, input_components_to, num_parallel_execs, input_components.size());

  std::vector<BYTEArrayVector> aux_auth_data(num_eval_auths, BYTEArrayVector(2, CODEWORD_BYTES));
  BYTEArrayVector aux_auth_delta_data(2, CODEWORD_BYTES);

  std::mutex delta_updated_mutex;
  std::condition_variable delta_updated_cond_val;
  bool delta_updated = false;
  std::tuple<std::mutex&, std::condition_variable&, bool&> delta_signal = make_tuple(std::ref(delta_updated_mutex), std::ref(delta_updated_cond_val), std::ref(delta_updated));

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    uint64_t exec_prg_counter = curr_prg_counter;
    curr_prg_counter += FIXED_PRG_INC_NUMBER;

    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();
    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &aux_auth_data, &aux_auth_delta_data, &delta_signal, &eval_auths_from, &eval_auths_to, &input_components, &input_components_from, &input_components_to, exec_id, exec_prg_counter, check_factor, negate_check_factor] (int id) {

      uint32_t exec_num_auths = eval_auths_to[exec_id] - eval_auths_from[exec_id];

      float slack_val, repl_factor;
      ComputeCheckFraction(check_factor, exec_num_auths, slack_val, repl_factor, negate_check_factor);

      uint32_t exec_num_total_auths = ceil(repl_factor * exec_num_auths);

      CommitAuthAndCutAndChoose(exec_common_tools, exec_num_total_auths, exec_prg_counter, check_factor, negate_check_factor, eval_auths_from[exec_id], eval_auths_to[exec_id], aux_auth_data, aux_auth_delta_data, delta_signal);

      DecommitEvalInputPermBits(exec_common_tools, input_components, input_components_from[exec_id], input_components_to[exec_id]);
    });
  }

  for (std::future<void>& r : execs_finished) {
    r.wait();
  }

  auto prepare_eval_commit_cnc_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(prepare_eval_commit_cnc_begin, prepare_eval_commit_cnc_end, num_circuit_buckets, "PrepareEvalCommitCNC");
#endif

  std::vector<std::vector<int>> session_circuit_buckets_from(num_parallel_execs);
  std::vector<std::vector<int>> session_circuit_buckets_to(num_parallel_execs);

  for (int i = 0; i < circuit_info.size(); ++i) {
    std::string& session_component_name(std::get<0>(circuit_info[i]));
    Circuit& session_circuits(std::get<1>(circuit_info[i]));
    uint64_t num_session_circuit_buckets = std::get<2>(circuit_info[i]);

    uint64_t num_session_auth_buckets = num_session_circuit_buckets * session_circuits.num_out_wires;
    uint64_t session_auth_bytes = 2 * CSEC_BYTES * num_session_auth_buckets;
    uint64_t session_auth_auxdata_bytes = 2 * CODEWORD_BYTES * num_session_auth_buckets;

    std::vector<int> tmp_from, tmp_to;
    PartitionBufferFixedNum(tmp_from, tmp_to, num_parallel_execs, num_session_circuit_buckets);
    for (int j = 0; j < num_parallel_execs; ++j) {
      session_circuit_buckets_from[j].push_back(tmp_from[j]);
      session_circuit_buckets_to[j].push_back(tmp_to[j]);
    }
  }

  uint8_t bucket_seed[CSEC_BYTES];
  common_tools.chan.ReceiveBlocking(bucket_seed, CSEC_BYTES);

  std::vector<uint32_t> permuted_eval_ids(num_eval_auths);
  std::vector<uint32_t> permuted_eval_ids_inv(num_eval_auths);
  std::iota(std::begin(permuted_eval_ids), std::end(permuted_eval_ids), 0);
  PermuteArray(permuted_eval_ids.data(), num_eval_auths, bucket_seed);
  for (int i = 0; i < num_eval_auths; ++i) {
    permuted_eval_ids_inv[permuted_eval_ids[i]] = i;
  }

  auto prepare_eval_bucketing_begin = GET_TIME();

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {
    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &aux_auth_data, &aux_auth_delta_data, &session_circuit_buckets_from, &session_circuit_buckets_to, exec_id, &permuted_eval_ids_inv, &input_components, &input_components_from, &input_components_to, &input_components_auth_start_pos, auth_size] (int id) {

      BucketAllAuths(exec_common_tools, auth_size, permuted_eval_ids_inv, session_circuit_buckets_from[exec_id], session_circuit_buckets_to[exec_id], aux_auth_data, aux_auth_delta_data, input_components, input_components_from[exec_id], input_components_to[exec_id], input_components_auth_start_pos);
    });
  }
  for (std::future<void>& r : execs_finished) {
    r.wait();
  }
  auto prepare_eval_bucketing_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(prepare_eval_bucketing_begin, prepare_eval_bucketing_end, num_circuit_buckets, "PrepareEvalBucketing");
#endif

  PrepareInputBuckets(input_components, num_parallel_execs);

  //OTX code cannot be run in parallel with a global delta
  PreprocessEvalInputOTs(input_components);
}

void DuploConstructor::EvalComponents(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& const_output_keys, uint32_t num_parallel_execs, bool receive_output_keys) {

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

    futures.emplace_back(thread_pool.push([this, &exec_common_tools, &components, &components_from, &components_to, &inputs, &const_output_keys, exec_inputs_used, exec_id, receive_output_keys] (int id) {

      uint32_t exec_num_components = components_to[exec_id] - components_from[exec_id];

      //Construct aux information
      std::vector<uint32_t> eval_inp_sizes, const_inp_sizes, eval_inp_pos, const_inp_pos;
      uint32_t num_total_eval_inputs = 0;
      uint32_t num_total_const_inputs = 0;
      uint32_t num_total_const_outputs = 0;
      for (int i = 0; i < exec_num_components; ++i) {
        uint32_t curr_component = components_from[exec_id] + i;
        std::string component_name = std::get<0>(components[curr_component]);
        Circuit& circuit = string_to_circuit_map[component_name];

        eval_inp_pos.emplace_back(num_total_eval_inputs);
        const_inp_pos.emplace_back(num_total_const_inputs);

        num_total_eval_inputs += circuit.num_eval_inp_wires;
        num_total_const_inputs += circuit.num_const_inp_wires;
        num_total_const_outputs += circuit.num_const_out_wires;

        eval_inp_sizes.emplace_back(circuit.num_eval_inp_wires);
        const_inp_sizes.emplace_back(circuit.num_const_inp_wires);
      }

      BYTEArrayVector e(BITS_TO_BYTES(num_total_eval_inputs), 1);
      exec_common_tools.chan.ReceiveBlocking(e.GetArray(), e.size);

      std::vector<uint8_t*> e_vec(exec_num_components);
      uint32_t inc_pos = 0;
      for (int i = 0; i < exec_num_components; ++i) {
        e_vec[i] = e.GetArray() + inc_pos;
        inc_pos += BITS_TO_BYTES(eval_inp_sizes[i]);
      }

      //Read all required dot input masks and their global delta
      BYTEArrayVector input_masks_shares;
      BYTEArrayVector input_masks_delta_shares;
      if (num_total_eval_inputs > 0) {
        persistent_storage.ReadBuckets(CONST_PREPROCESS_PREFIX, INPUT_MASKS_AUXDATA, exec_inputs_used, num_total_eval_inputs, input_masks_shares);
        persistent_storage.ReadBuckets(CONST_PREPROCESS_PREFIX, INPUT_MASKS_DELTA_AUXDATA, 0, 2, input_masks_delta_shares);
      }

      std::vector<uint8_t> key_decommits(num_total_const_inputs * CSEC_BYTES +
                                         (num_total_eval_inputs + exec_num_components) * 2 * CODEWORD_BYTES);
      uint8_t* const_keys = key_decommits.data();
      uint8_t* eval_keys_start_share0 = const_keys + num_total_const_inputs * CSEC_BYTES;
      uint8_t* deltas_start_share0 = eval_keys_start_share0 + num_total_eval_inputs * CODEWORD_BYTES;

      uint8_t* eval_keys_start_share1 = deltas_start_share0 + exec_num_components * CODEWORD_BYTES;
      uint8_t* deltas_start_share1 = eval_keys_start_share1 + num_total_eval_inputs * CODEWORD_BYTES;

      //Send input keys.
      for (int i = 0; i < exec_num_components; ++i) {
        uint32_t curr_component = components_from[exec_id] + i;
        std::string component_name = std::get<0>(components[curr_component]);
        uint32_t component_num = std::get<1>(components[curr_component]);
        Circuit& circuit = string_to_circuit_map[component_name];

        BYTEArrayVector component_aux_data;
        persistent_storage.ReadBuckets(component_name, AUXDATA, component_num, 1, component_aux_data);

        //Construct current component delta
        uint8_t component_delta[CSEC_BYTES];
        XOR_128(component_delta,
                ConstGarbledCircuit::delta_commit0(circuit, component_aux_data.GetArray()),
                ConstGarbledCircuit::delta_commit1(circuit, component_aux_data.GetArray()));

        //Construct const input keys
        for (int j = 0; j < const_inp_sizes[i]; ++j) {
          XOR_128(const_keys + (const_inp_pos[i] + j) * CSEC_BYTES,
                  ConstGarbledCircuit::inp_key_commit0(circuit, component_aux_data.GetArray(), j),
                  ConstGarbledCircuit::inp_key_commit1(circuit, component_aux_data.GetArray(), j));
          if (GetBit(0, ConstGarbledCircuit::inp_bit_commit0(circuit, component_aux_data.GetArray(), j)) ^
              GetBit(0, ConstGarbledCircuit::inp_bit_commit1(circuit, component_aux_data.GetArray(), j)) ^
              GetBit(j, inputs[curr_component].data())) {
            XOR_128(const_keys + (const_inp_pos[i] + j) * CSEC_BYTES, component_delta);
          }
        }

        //Construct current component delta soldering
        std::copy(ConstGarbledCircuit::delta_commit0(circuit, component_aux_data.GetArray()),
                  ConstGarbledCircuit::delta_commit0(circuit, component_aux_data.GetArray() + CODEWORD_BYTES),
                  deltas_start_share0 + i * CODEWORD_BYTES);
        std::copy(ConstGarbledCircuit::delta_commit1(circuit, component_aux_data.GetArray()),
                  ConstGarbledCircuit::delta_commit1(circuit, component_aux_data.GetArray()) + CODEWORD_BYTES,
                  deltas_start_share1 + i * CODEWORD_BYTES);

        if (num_total_eval_inputs > 0) {
          XOR_CodeWords(deltas_start_share0 + i * CODEWORD_BYTES, input_masks_delta_shares[0]);
          XOR_CodeWords(deltas_start_share1 + i * CODEWORD_BYTES, input_masks_delta_shares[1]);
        }

        //Construct eval input keys
        for (int j = 0; j < eval_inp_sizes[i]; ++j) {
          //First copy eval keys
          std::copy(ConstGarbledCircuit::inp_key_commit0(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j),
                    ConstGarbledCircuit::inp_key_commit0(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j + 1),
                    eval_keys_start_share0 + (eval_inp_pos[i] + j) * CODEWORD_BYTES);

          std::copy(ConstGarbledCircuit::inp_key_commit1(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j),
                    ConstGarbledCircuit::inp_key_commit1(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j + 1),
                    eval_keys_start_share1 + (eval_inp_pos[i] + j) * CODEWORD_BYTES);

          //XOR with mask keys
          XOR_CodeWords(eval_keys_start_share0 + (eval_inp_pos[i] + j) * CODEWORD_BYTES, input_masks_shares[eval_inp_pos[i] + j]);
          XOR_CodeWords(eval_keys_start_share1 + (eval_inp_pos[i] + j) * CODEWORD_BYTES, input_masks_shares[eval_inp_pos[i] + j] + CODEWORD_BYTES);

          //If e_j for this component is set XOR input_mask_delta onto the decommit
          if (GetBit(j, e_vec[i])) {
            XOR_CodeWords(eval_keys_start_share0 + (eval_inp_pos[i] + j) * CODEWORD_BYTES,
                          input_masks_delta_shares[0]);
            XOR_CodeWords(eval_keys_start_share1 + (eval_inp_pos[i] + j) * CODEWORD_BYTES,
                          input_masks_delta_shares[1]);
          }
        }
      }
      exec_common_tools.chan.Send(key_decommits.data(), key_decommits.size());

      if (receive_output_keys) {
        BYTEArrayVector exec_output_keys(num_total_const_outputs, CSEC_BYTES);
        exec_common_tools.chan.ReceiveBlocking(exec_output_keys.GetArray(), exec_output_keys.size);

        uint32_t curr_pos = 0;
        for (int i = 0; i < exec_num_components; ++i) {
          uint32_t curr_component = components_from[exec_id] + i;
          std::string component_name = std::get<0>(components[curr_component]);
          Circuit& circuit = string_to_circuit_map[component_name];
          const_output_keys[curr_component] = BYTEArrayVector(circuit.num_const_out_wires, CSEC_BYTES);

          std::copy(exec_output_keys[curr_pos],
                    exec_output_keys[curr_pos + circuit.num_const_out_wires], const_output_keys[curr_component].GetArray());
          curr_pos += circuit.num_const_out_wires;
        }
      }
    }));

  }

  for (std::future<void>& future : futures) {
    future.wait();
  }
}

void DuploConstructor::DecodeKeys(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<BYTEArrayVector>& output_keys, std::vector<std::vector<uint8_t>>& outputs, uint32_t num_parallel_execs) {

  std::vector<int> components_from, components_to;
  PartitionBufferFixedNum(components_from, components_to, num_parallel_execs, components.size());

  std::vector<std::future<void>> futures;
  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    futures.emplace_back(thread_pool.push([this, &exec_common_tools, &components, &components_from, &components_to, &output_keys, &outputs, exec_id] (int id) {

      uint32_t exec_num_components = components_to[exec_id] - components_from[exec_id];

      std::vector<BYTEArrayVector> output_decodings;
      DecommitOutPermBits(exec_common_tools, components, components_from[exec_id], components_to[exec_id], output_decodings);

      for (int i = 0; i < exec_num_components; ++i) {
        uint32_t curr_component = components_from[exec_id] + i;
        std::string component_name = std::get<0>(components[curr_component]);
        Circuit& circuit = string_to_circuit_map[component_name];

        outputs[curr_component] = std::vector<uint8_t>(BITS_TO_BYTES(circuit.num_const_out_wires));

        DecodeGarbledOutput(output_keys[curr_component].GetArray(), output_decodings[i].GetArray(), outputs[curr_component].data(), circuit.num_const_out_wires);
      }
    }));
  }

  for (std::future<void>& f : futures) {
    f.wait();
  }
}

void DuploConstructor::CommitGarbleAndCutAndChoose(CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_num_total_garbled, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_circuits_from, uint32_t exec_eval_circuits_to, std::vector<ConstGarbledCircuit>& aux_garbled_circuits_data) {

  uint32_t num_inp_keys, num_out_keys, num_deltas, num_commit_keys, num_base_keys, inp_keys_idx, out_keys_idx, deltas_idx;
  ComputeIndices(exec_num_total_garbled, circuit, num_inp_keys, num_out_keys, num_deltas, num_commit_keys, num_base_keys, inp_keys_idx, out_keys_idx, deltas_idx);

  CommitSender commit_snd(exec_common_tools, commit_seed_OTs0.GetArray(), commit_seed_OTs1.GetArray());
  BitCommitSender bit_commit_snd(exec_common_tools, commit_seed_OTs0[CODEWORD_BITS], commit_seed_OTs1[CODEWORD_BITS]);

  BYTEArrayVector commit_keys_share0(num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector commit_keys_share1(num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector commit_perm_bits_share0(num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector commit_perm_bits_share1(num_base_keys, BIT_CODEWORD_BYTES);

  //Commit to the input/output wires and Deltas of all garbled circuits.
  commit_snd.Commit(num_commit_keys, commit_keys_share0, commit_keys_share1, exec_prg_counter, deltas_idx);
  //Commit to perm bits
  bit_commit_snd.Commit(num_base_keys, commit_perm_bits_share0, commit_perm_bits_share1, exec_prg_counter);

  //Buffers
  BYTEArrayVector garbling_inp_keys(circuit.num_inp_wires, CSEC_BYTES);
  BYTEArrayVector garbling_out_keys(circuit.num_out_wires, CSEC_BYTES);
  uint8_t delta[CSEC_BYTES];

  GarblingHandler gh;
  std::vector<ConstGarbledCircuit> garbled_circuits(exec_num_total_garbled, ConstGarbledCircuit(circuit));

  BYTEArrayVector garb_circuit_hashes(exec_num_total_garbled, CSEC_BYTES);
  BYTEArrayVector out_wire_commit_corrections(num_out_keys, CSEC_BYTES);

  //Do all GARBLING and HASHING of circuits
  for (int i = 0; i < exec_num_total_garbled; ++i) {
    //Compute the delta used for this circuit
    XOR_128(delta, commit_keys_share0[deltas_idx + i], commit_keys_share1[deltas_idx + i]);

    //Compute the input used for this circuit, if lsb(input key_j) == 1 it means the committed key is the 1 key and we therefore flip the key using delta_i so that we garbled with the committed 0 keys.
    for (int j = 0; j < circuit.num_inp_wires; ++j) {
      XOR_128(garbling_inp_keys[j], commit_keys_share0[inp_keys_idx + i * circuit.num_inp_wires + j], commit_keys_share1[inp_keys_idx + i * circuit.num_inp_wires + j]);

      if (GetBit(0, commit_perm_bits_share0[inp_keys_idx + i * circuit.num_inp_wires + j]) ^ GetBit(0, commit_perm_bits_share1[inp_keys_idx + i * circuit.num_inp_wires + j])) {
        XOR_128(garbling_inp_keys[j], delta);
      }
    }

    gh.GarbleCircuit(garbling_inp_keys.GetArray(), garbling_out_keys.GetArray(), delta, garbled_circuits[i], garb_circuit_hashes[i]);

    //Compute the output key corrections for this circuit. if lsb(output key_j) == 1 it means the committed key is supposed to be the 1 key and we therefore flip the key using delta so this becomes true.
    for (int j = 0; j < circuit.num_out_wires; ++j) {
      XOR_128(out_wire_commit_corrections[i * circuit.num_out_wires + j], commit_keys_share0[out_keys_idx + i * circuit.num_out_wires + j], commit_keys_share1[out_keys_idx + i * circuit.num_out_wires + j]);
      XOR_128(out_wire_commit_corrections[i * circuit.num_out_wires + j], garbling_out_keys[j]);

      if (GetBit(0, commit_perm_bits_share0[out_keys_idx + i * circuit.num_out_wires + j]) ^ GetBit(0, commit_perm_bits_share1[out_keys_idx + i * circuit.num_out_wires + j])) {
        XOR_128(out_wire_commit_corrections[i * circuit.num_out_wires + j], delta);
      }
    }
  }

  //Send output keys commit corrections and hashes of tables. Thereby "commits" constructor to the tables
  exec_common_tools.chan.Send(out_wire_commit_corrections.GetArray(), out_wire_commit_corrections.size);
  exec_common_tools.chan.Send(garb_circuit_hashes.GetArray(), garb_circuit_hashes.size);

  ///////////////////////// CUT-AND-CHOOSE /////////////////////////

  //Receive challenge seed
  uint8_t cnc_seed[CSEC_BYTES];
  exec_common_tools.chan.ReceiveBlocking(cnc_seed, CSEC_BYTES);

  //Select challenge circuits based on cnc_seed
  uint32_t num_bytes_exec_num_total_garbled = BITS_TO_BYTES(exec_num_total_garbled);
  std::vector<uint8_t> cnc_check_circuits(num_bytes_exec_num_total_garbled);
  PRNG cnc_rand;
  cnc_rand.SetSeed(cnc_seed);

  WeightedRandomString(cnc_check_circuits.data(), check_factor, num_bytes_exec_num_total_garbled, cnc_rand, negate_check_factor);
  int num_checked_circuits = countSetBits(cnc_check_circuits.data(), 0, exec_num_total_garbled - 1);

  //Compute indices for convenient indexing
  uint32_t cnc_num_inp_keys, cnc_num_out_keys, cnc_num_deltas, cnc_num_commit_keys, cnc_num_base_keys, cnc_inp_keys_idx, cnc_out_keys_idx, cnc_deltas_idx;
  ComputeIndices(num_checked_circuits, circuit, cnc_num_inp_keys, cnc_num_out_keys, cnc_num_deltas, cnc_num_commit_keys, cnc_num_base_keys, cnc_inp_keys_idx, cnc_out_keys_idx, cnc_deltas_idx);

  //Arrays for holding the decommit shares of the decommited keys
  BYTEArrayVector cnc_keys_share0(cnc_num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector cnc_keys_share1(cnc_num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector cnc_keys(cnc_num_commit_keys, CSEC_BYTES);

  //Arrays for holding the decommit shares of the decommit perm bits
  BYTEArrayVector cnc_perm_bits_share0(cnc_num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector cnc_perm_bits_share1(cnc_num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector cnc_commit_perm_bits(BITS_TO_BYTES(cnc_num_base_keys), 1);

  uint32_t current_check_circuit_idx = 0;
  uint32_t current_eval_circuit_idx = exec_eval_circuits_from;
  bool completed_eval_copy = false;
  for (int i = 0; i < exec_num_total_garbled; ++i) {
    if (GetBit(i, cnc_check_circuits.data())) { //Checked circuit

      //Add delta
      std::copy(commit_keys_share0[deltas_idx + i], commit_keys_share0[deltas_idx + (i + 1)], cnc_keys_share0[cnc_deltas_idx + current_check_circuit_idx]);
      std::copy(commit_keys_share1[deltas_idx + i], commit_keys_share1[deltas_idx + (i + 1)], cnc_keys_share1[cnc_deltas_idx + current_check_circuit_idx]);

      //Compute the delta value
      XOR_128(cnc_keys[cnc_deltas_idx + current_check_circuit_idx], cnc_keys_share0[cnc_deltas_idx + current_check_circuit_idx], cnc_keys_share1[cnc_deltas_idx + current_check_circuit_idx]);

      //Add inputs
      std::copy(commit_keys_share0[inp_keys_idx + i * circuit.num_inp_wires], commit_keys_share0[inp_keys_idx + (i + 1) * circuit.num_inp_wires], cnc_keys_share0[cnc_inp_keys_idx + current_check_circuit_idx * circuit.num_inp_wires]);
      std::copy(commit_keys_share1[inp_keys_idx + i * circuit.num_inp_wires], commit_keys_share1[inp_keys_idx + (i + 1) * circuit.num_inp_wires], cnc_keys_share1[cnc_inp_keys_idx + current_check_circuit_idx * circuit.num_inp_wires]);

      //Compute the input values
      for (int j = 0; j < circuit.num_inp_wires; ++j) {

        XORBit(
          cnc_inp_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j,
          GetBit(0, commit_perm_bits_share0[inp_keys_idx + i * circuit.num_inp_wires + j]),
          GetBit(0, commit_perm_bits_share1[inp_keys_idx + i * circuit.num_inp_wires + j]), cnc_commit_perm_bits.GetArray());

        //Flip the key and decommit values
        if (GetBit(cnc_inp_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j, cnc_commit_perm_bits.GetArray())) {
          XOR_CodeWords(cnc_keys_share0[cnc_inp_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j], cnc_keys_share0[cnc_deltas_idx + current_check_circuit_idx]);
          XOR_CodeWords(cnc_keys_share1[cnc_inp_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j], cnc_keys_share1[cnc_deltas_idx + current_check_circuit_idx]);
        }

        //Compute the input keys
        XOR_128(cnc_keys[cnc_inp_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j], cnc_keys_share0[cnc_inp_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j], cnc_keys_share1[cnc_inp_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j]);
      }

      //Add outputs
      std::copy(commit_keys_share0[out_keys_idx + i * circuit.num_out_wires], commit_keys_share0[out_keys_idx + (i + 1) * circuit.num_out_wires], cnc_keys_share0[cnc_out_keys_idx + current_check_circuit_idx * circuit.num_out_wires]);
      std::copy(commit_keys_share1[out_keys_idx + i * circuit.num_out_wires], commit_keys_share1[out_keys_idx + (i + 1) * circuit.num_out_wires], cnc_keys_share1[cnc_out_keys_idx + current_check_circuit_idx * circuit.num_out_wires]);

      //Compute the output values
      for (int j = 0; j < circuit.num_out_wires; ++j) {

        XORBit(
          cnc_out_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j,
          GetBit(0, commit_perm_bits_share0[out_keys_idx + i * circuit.num_out_wires + j]),
          GetBit(0, commit_perm_bits_share1[out_keys_idx + i * circuit.num_out_wires + j]), cnc_commit_perm_bits.GetArray());

        //Flip the key and decommit values
        if (GetBit(cnc_out_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j, cnc_commit_perm_bits.GetArray())) {
          XOR_CodeWords(cnc_keys_share0[cnc_out_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j], cnc_keys_share0[cnc_deltas_idx + current_check_circuit_idx]);
          XOR_CodeWords(cnc_keys_share1[cnc_out_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j], cnc_keys_share1[cnc_deltas_idx + current_check_circuit_idx]);
        }

        //Compute the output keys
        XOR_128(cnc_keys[cnc_out_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j], cnc_keys_share0[cnc_out_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j], cnc_keys_share1[cnc_out_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j]);
      }

      //Add input permutation bits
      std::copy(commit_perm_bits_share0[inp_keys_idx + i * circuit.num_inp_wires], commit_perm_bits_share0[inp_keys_idx + (i + 1) * circuit.num_inp_wires], cnc_perm_bits_share0[cnc_inp_keys_idx + current_check_circuit_idx * circuit.num_inp_wires]);
      std::copy(commit_perm_bits_share1[inp_keys_idx + i * circuit.num_inp_wires], commit_perm_bits_share1[inp_keys_idx + (i + 1) * circuit.num_inp_wires], cnc_perm_bits_share1[cnc_inp_keys_idx + current_check_circuit_idx * circuit.num_inp_wires]);

      //Add output permutation bits
      std::copy(commit_perm_bits_share0[out_keys_idx + i * circuit.num_out_wires], commit_perm_bits_share0[out_keys_idx + (i + 1) * circuit.num_out_wires], cnc_perm_bits_share0[cnc_out_keys_idx + current_check_circuit_idx * circuit.num_out_wires]);
      std::copy(commit_perm_bits_share1[out_keys_idx + i * circuit.num_out_wires], commit_perm_bits_share1[out_keys_idx + (i + 1) * circuit.num_out_wires], cnc_perm_bits_share1[cnc_out_keys_idx + current_check_circuit_idx * circuit.num_out_wires]);

      ++current_check_circuit_idx;
    } else if (current_eval_circuit_idx < exec_eval_circuits_to) {

      //Copy Delta
      std::copy(commit_keys_share0[deltas_idx + i], commit_keys_share0[deltas_idx + (i + 1)], aux_garbled_circuits_data[current_eval_circuit_idx].delta_commit0());
      std::copy(commit_keys_share1[deltas_idx + i], commit_keys_share1[deltas_idx + (i + 1)], aux_garbled_circuits_data[current_eval_circuit_idx].delta_commit1());

      //Copy inputs
      std::copy(commit_keys_share0[inp_keys_idx + i * circuit.num_inp_wires], commit_keys_share0[inp_keys_idx + (i + 1) * circuit.num_inp_wires], aux_garbled_circuits_data[current_eval_circuit_idx].inp_key_commit0());
      std::copy(commit_keys_share1[inp_keys_idx + i * circuit.num_inp_wires], commit_keys_share1[inp_keys_idx + (i + 1) * circuit.num_inp_wires], aux_garbled_circuits_data[current_eval_circuit_idx].inp_key_commit1());

      //Copy outputs
      std::copy(commit_keys_share0[out_keys_idx + i * circuit.num_out_wires], commit_keys_share0[out_keys_idx + (i + 1) * circuit.num_out_wires], aux_garbled_circuits_data[current_eval_circuit_idx].out_key_commit0());
      std::copy(commit_keys_share1[out_keys_idx + i * circuit.num_out_wires], commit_keys_share1[out_keys_idx + (i + 1) * circuit.num_out_wires], aux_garbled_circuits_data[current_eval_circuit_idx].out_key_commit1());

      //Copy input permutation bits
      std::copy(commit_perm_bits_share0[inp_keys_idx + i * circuit.num_inp_wires], commit_perm_bits_share0[inp_keys_idx + (i + 1) * circuit.num_inp_wires], aux_garbled_circuits_data[current_eval_circuit_idx].inp_bit_commit0());
      std::copy(commit_perm_bits_share1[inp_keys_idx + i * circuit.num_inp_wires], commit_perm_bits_share1[inp_keys_idx + (i + 1) * circuit.num_inp_wires], aux_garbled_circuits_data[current_eval_circuit_idx].inp_bit_commit1());

      //Copy output permutation bits
      std::copy(commit_perm_bits_share0[out_keys_idx + i * circuit.num_out_wires], commit_perm_bits_share0[out_keys_idx + (i + 1) * circuit.num_out_wires], aux_garbled_circuits_data[current_eval_circuit_idx].out_bit_commit0());
      std::copy(commit_perm_bits_share1[out_keys_idx + i * circuit.num_out_wires], commit_perm_bits_share1[out_keys_idx + (i + 1) * circuit.num_out_wires], aux_garbled_circuits_data[current_eval_circuit_idx].out_bit_commit1());

      ++current_eval_circuit_idx;
    } else {
      completed_eval_copy = true;
    }
  }

  if (!completed_eval_copy) {
    std::cout << "Problem. Not enough eval circuits! Params should be set so this never occurs" << std::endl;
  }

  //Send postulated perm bit values and prove correct using BatchDecommit
  exec_common_tools.chan.Send(cnc_commit_perm_bits.GetArray(), cnc_commit_perm_bits.size);
  bit_commit_snd.BatchDecommit(cnc_perm_bits_share0.GetArray(), cnc_perm_bits_share1.GetArray(), cnc_num_base_keys);

  //BatchDecommit the cut-and-choose input and output keys. Needs to be done after BatchDecommit of perm bit values.
  exec_common_tools.chan.Send(cnc_keys.GetArray(), cnc_keys.size);
  commit_snd.BatchDecommit(cnc_keys_share0.GetArray(), cnc_keys_share1.GetArray(), cnc_num_commit_keys);
}

void DuploConstructor::BucketAndSendEvalCircuits(std::string component_type, CommonTools& exec_common_tools, Circuit& circuit, uint32_t bucket_size, std::vector<uint32_t>& permuted_eval_ids_inv, uint32_t exec_buckets_from, uint32_t exec_buckets_to, std::vector<ConstGarbledCircuit>& aux_garbled_circuits_data) {

  uint64_t exec_num_buckets = exec_buckets_to - exec_buckets_from;
  uint64_t exec_num_eval_circuits = exec_num_buckets * bucket_size;

  uint64_t garbled_table_size = GarbledCircuit::TotalTableSize(circuit);
  uint64_t constr_aux_size = ConstGarbledCircuit::AuxDataSize(circuit);

  //Res buffers
  BYTEArrayVector exec_permuted_aux_info(exec_num_eval_circuits, constr_aux_size); //TODO: Can be / bucket_size to save space. Then just need to lookup using aux_garbled_circuits_data[permuted_eval_ids_inv[i]].GetAuxArray() instead of exec_permuted_aux_info[current_idx].
  BYTEArrayVector garbled_tables(exec_num_eval_circuits, garbled_table_size);

  BYTEArrayVector exec_write_head_auxdata(exec_num_buckets, constr_aux_size); // Holds the head circuits' info only. Look at TODO for exec_permuted_aux_info. This might not be necessarry if we change that one.

  //Tmp buffers
  ConstGarbledCircuit garbled_circuit(circuit, 1);
  BYTEArrayVector input_keys(circuit.num_inp_wires, CSEC_BYTES);
  BYTEArrayVector out_buffer(circuit.num_out_wires, CSEC_BYTES);
  uint8_t delta[CSEC_BYTES];

  GarblingHandler gh;
  for (int i = 0; i < exec_num_eval_circuits; ++i) {
    //swap current index with i!
    uint32_t global_circuit_index = exec_buckets_from * bucket_size + i;

    std::copy(aux_garbled_circuits_data[permuted_eval_ids_inv[global_circuit_index]].GetAuxArray(), aux_garbled_circuits_data[permuted_eval_ids_inv[global_circuit_index]].GetAuxArray() + constr_aux_size, exec_permuted_aux_info[i]);

    //Compute garbling keys
    XOR_128(delta, ConstGarbledCircuit::delta_commit0(circuit, exec_permuted_aux_info[i]),
            ConstGarbledCircuit::delta_commit1(circuit, exec_permuted_aux_info[i]));
    for (int j = 0; j < circuit.num_inp_wires; ++j) {
      XOR_128(input_keys[j], ConstGarbledCircuit::inp_key_commit0(circuit, exec_permuted_aux_info[i], j), ConstGarbledCircuit::inp_key_commit1(circuit, exec_permuted_aux_info[i], j));

      if (GetBit(0, ConstGarbledCircuit::inp_bit_commit0(circuit, exec_permuted_aux_info[i], j)) ^ GetBit(0, ConstGarbledCircuit::inp_bit_commit1(circuit, exec_permuted_aux_info[i], j))) {
        XOR_128(input_keys[j], delta);
      }
    }

    //Garble circuit and write resulting tables to garbled_tables
    gh.GarbleCircuit(input_keys.GetArray(), out_buffer.GetArray(), delta, garbled_circuit);
    std::copy(garbled_circuit.GetTables(), garbled_circuit.GetTables() + garbled_circuit.size, garbled_tables[i]);
  }

  exec_common_tools.chan.Send(garbled_tables.GetArray(), garbled_tables.size);
  //garbled_tables could be deleted at this point to save space!

  ////////////////////////////Soldering/////////////////////////////////////

  uint32_t num_soldering_circuits = (bucket_size - 1) * exec_num_eval_circuits;

  uint32_t solder_num_inp_keys, solder_num_out_keys, solder_num_deltas, solder_num_commit_keys, solder_num_base_keys, solder_inp_keys_idx, solder_out_keys_idx, solder_deltas_idx;
  ComputeIndices(num_soldering_circuits, circuit, solder_num_inp_keys, solder_num_out_keys, solder_num_deltas, solder_num_commit_keys, solder_num_base_keys, solder_inp_keys_idx, solder_out_keys_idx, solder_deltas_idx);

  uint32_t curr_head_circuit, curr_circuit, curr_solder_write_pos;

  BYTEArrayVector solder_keys_share0(solder_num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector solder_keys_share1(solder_num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector solder_keys(solder_num_commit_keys, CSEC_BYTES);

  BYTEArrayVector solder_perm_bits_share0(solder_num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector solder_perm_bits_share1(solder_num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector solder_commit_perm_bits(BITS_TO_BYTES(solder_num_base_keys), 1);

  BYTEArrayVector head_inp_keys(circuit.num_inp_wires, CSEC_BYTES);
  BYTEArrayVector head_out_keys(circuit.num_out_wires, CSEC_BYTES);
  BYTEArrayVector head_inp_perm_bits(BITS_TO_BYTES(circuit.num_inp_wires), 1);
  BYTEArrayVector head_out_perm_bits(BITS_TO_BYTES(circuit.num_out_wires), 1);
  uint8_t head_delta[CSEC_BYTES];
  uint8_t curr_circuit_delta[CSEC_BYTES];
  for (int i = 0; i < exec_num_buckets; ++i) {
    curr_head_circuit = i * bucket_size;
    XOR_128(head_delta,
            ConstGarbledCircuit::delta_commit0(circuit, exec_permuted_aux_info[curr_head_circuit]),
            ConstGarbledCircuit::delta_commit1(circuit, exec_permuted_aux_info[curr_head_circuit]));

    for (int j = 0; j < circuit.num_inp_wires; ++j) {
      XOR_128(head_inp_keys[j],
              ConstGarbledCircuit::inp_key_commit0(circuit, exec_permuted_aux_info[curr_head_circuit], j),
              ConstGarbledCircuit::inp_key_commit1(circuit, exec_permuted_aux_info[curr_head_circuit], j));

      XORBit(j, GetBit(0, ConstGarbledCircuit::inp_bit_commit0(circuit, exec_permuted_aux_info[curr_head_circuit], j)),
             GetBit(0, ConstGarbledCircuit::inp_bit_commit1(circuit, exec_permuted_aux_info[curr_head_circuit], j)), head_inp_perm_bits.GetArray());
    }

    for (int j = 0; j < circuit.num_out_wires; ++j) {
      XOR_128(head_out_keys[j],
              ConstGarbledCircuit::out_key_commit0(circuit, exec_permuted_aux_info[curr_head_circuit], j),
              ConstGarbledCircuit::out_key_commit1(circuit, exec_permuted_aux_info[curr_head_circuit], j));

      XORBit(j, GetBit(0, ConstGarbledCircuit::out_bit_commit0(circuit, exec_permuted_aux_info[curr_head_circuit], j)),
             GetBit(0, ConstGarbledCircuit::out_bit_commit1(circuit, exec_permuted_aux_info[curr_head_circuit], j)), head_out_perm_bits.GetArray());
    }

    //Store the current head circuit info for writing to disc
    std::copy(exec_permuted_aux_info[curr_head_circuit], exec_permuted_aux_info[curr_head_circuit + 1], exec_write_head_auxdata[i]);

    //Do each circuit in the bucket
    for (int l = 1; l < bucket_size; ++l) {
      curr_circuit = curr_head_circuit + l;
      curr_solder_write_pos = curr_circuit - (i + 1);

      //Compute the delta soldering
      XOR_128(curr_circuit_delta, ConstGarbledCircuit::delta_commit0(circuit, exec_permuted_aux_info[curr_circuit]), ConstGarbledCircuit::delta_commit1(circuit, exec_permuted_aux_info[curr_circuit]));

      std::copy(curr_circuit_delta, curr_circuit_delta + CSEC_BYTES, solder_keys[solder_deltas_idx + curr_solder_write_pos]);
      XOR_128(solder_keys[solder_deltas_idx + curr_solder_write_pos], head_delta);

      //Add delta decommits
      std::copy(ConstGarbledCircuit::delta_commit0(circuit, exec_permuted_aux_info[curr_circuit]),
                ConstGarbledCircuit::delta_commit0(circuit, exec_permuted_aux_info[curr_circuit]) + CODEWORD_BYTES,
                solder_keys_share0[solder_deltas_idx + curr_solder_write_pos]);
      XOR_CodeWords(solder_keys_share0[solder_deltas_idx + curr_solder_write_pos], ConstGarbledCircuit::delta_commit0(circuit, exec_permuted_aux_info[curr_head_circuit]));

      std::copy(ConstGarbledCircuit::delta_commit1(circuit, exec_permuted_aux_info[curr_circuit]),
                ConstGarbledCircuit::delta_commit1(circuit, exec_permuted_aux_info[curr_circuit]) + CODEWORD_BYTES,
                solder_keys_share1[solder_deltas_idx + curr_solder_write_pos]);
      XOR_CodeWords(solder_keys_share1[solder_deltas_idx + curr_solder_write_pos], ConstGarbledCircuit::delta_commit1(circuit, exec_permuted_aux_info[curr_head_circuit]));

      for (int j = 0; j < circuit.num_inp_wires; ++j) {
        //Add input soldering
        XOR_128(solder_keys[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j], ConstGarbledCircuit::inp_key_commit0(circuit, exec_permuted_aux_info[curr_circuit], j), ConstGarbledCircuit::inp_key_commit1(circuit, exec_permuted_aux_info[curr_circuit], j));

        XOR_128(solder_keys[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j], head_inp_keys[j]);

        //Add input decommits
        std::copy(ConstGarbledCircuit::inp_key_commit0(circuit, exec_permuted_aux_info[curr_circuit], j),
                  ConstGarbledCircuit::inp_key_commit0(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_keys_share0[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j]);
        XOR_CodeWords(solder_keys_share0[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j], ConstGarbledCircuit::inp_key_commit0(circuit, exec_permuted_aux_info[curr_head_circuit], j));

        std::copy(ConstGarbledCircuit::inp_key_commit1(circuit, exec_permuted_aux_info[curr_circuit], j),
                  ConstGarbledCircuit::inp_key_commit1(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_keys_share1[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j]);
        XOR_CodeWords(solder_keys_share1[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j], ConstGarbledCircuit::inp_key_commit1(circuit, exec_permuted_aux_info[curr_head_circuit], j));

        //Add input permutation bit soldering
        XORBit(
          solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j,
          GetBit(0, ConstGarbledCircuit::inp_bit_commit0(circuit, exec_permuted_aux_info[curr_circuit], j)),
          GetBit(0, ConstGarbledCircuit::inp_bit_commit1(circuit, exec_permuted_aux_info[curr_circuit], j)), solder_commit_perm_bits.GetArray());

        XORBit(
          solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j, GetBit(j, head_inp_perm_bits.GetArray()), solder_commit_perm_bits.GetArray());

        //If xor of perm bits == 1 we XOR delta onto the soldering
        if (GetBit(solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j, solder_commit_perm_bits.GetArray())) {

          XOR_128(solder_keys[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j], curr_circuit_delta);

          XOR_CodeWords(solder_keys_share0[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j], ConstGarbledCircuit::delta_commit0(circuit, exec_permuted_aux_info[curr_circuit]));
          XOR_CodeWords(solder_keys_share1[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j], ConstGarbledCircuit::delta_commit1(circuit, exec_permuted_aux_info[curr_circuit]));
        }

        //Add input permutation bit soldering decommit
        std::copy(ConstGarbledCircuit::inp_bit_commit0(circuit, exec_permuted_aux_info[curr_circuit], j),
                  ConstGarbledCircuit::inp_bit_commit0(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_perm_bits_share0[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j]);
        XOR_BitCodeWords(solder_perm_bits_share0[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j], ConstGarbledCircuit::inp_bit_commit0(circuit, exec_permuted_aux_info[curr_head_circuit], j));

        std::copy(ConstGarbledCircuit::inp_bit_commit1(circuit, exec_permuted_aux_info[curr_circuit], j),
                  ConstGarbledCircuit::inp_bit_commit1(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_perm_bits_share1[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j]);
        XOR_BitCodeWords(solder_perm_bits_share1[solder_inp_keys_idx + curr_solder_write_pos * circuit.num_inp_wires + j], ConstGarbledCircuit::inp_bit_commit1(circuit, exec_permuted_aux_info[curr_head_circuit], j));
      }

      for (int j = 0; j < circuit.num_out_wires; ++j) {
        //Add output soldering
        XOR_128(solder_keys[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j], ConstGarbledCircuit::out_key_commit0(circuit, exec_permuted_aux_info[curr_circuit], j), ConstGarbledCircuit::out_key_commit1(circuit, exec_permuted_aux_info[curr_circuit], j));

        XOR_128(solder_keys[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j], head_out_keys[j]);

        //Add output decommits
        std::copy(ConstGarbledCircuit::out_key_commit0(circuit, exec_permuted_aux_info[curr_circuit], j),
                  ConstGarbledCircuit::out_key_commit0(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_keys_share0[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j]);
        XOR_CodeWords(solder_keys_share0[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j], ConstGarbledCircuit::out_key_commit0(circuit, exec_permuted_aux_info[curr_head_circuit], j));

        std::copy(ConstGarbledCircuit::out_key_commit1(circuit, exec_permuted_aux_info[curr_circuit], j),
                  ConstGarbledCircuit::out_key_commit1(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_keys_share1[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j]);
        XOR_CodeWords(solder_keys_share1[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j], ConstGarbledCircuit::out_key_commit1(circuit, exec_permuted_aux_info[curr_head_circuit], j));

        //Add output permutation bit soldering
        XORBit(
          solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j,
          GetBit(0, ConstGarbledCircuit::out_bit_commit0(circuit, exec_permuted_aux_info[curr_circuit], j)),
          GetBit(0, ConstGarbledCircuit::out_bit_commit1(circuit, exec_permuted_aux_info[curr_circuit], j)), solder_commit_perm_bits.GetArray());
        XORBit(
          solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j, GetBit(j, head_out_perm_bits.GetArray()), solder_commit_perm_bits.GetArray());

        //If xor of perm bits == 1 we XOR delta onto the soldering
        if (GetBit(solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j, solder_commit_perm_bits.GetArray())) {

          XOR_128(solder_keys[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j], curr_circuit_delta);

          XOR_CodeWords(solder_keys_share0[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j], ConstGarbledCircuit::delta_commit0(circuit, exec_permuted_aux_info[curr_circuit]));
          XOR_CodeWords(solder_keys_share1[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j], ConstGarbledCircuit::delta_commit1(circuit, exec_permuted_aux_info[curr_circuit]));
        }

        //Add output permutation bit soldering decommit
        std::copy(ConstGarbledCircuit::out_bit_commit0(circuit, exec_permuted_aux_info[curr_circuit], j),
                  ConstGarbledCircuit::out_bit_commit0(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_perm_bits_share0[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j]);
        XOR_BitCodeWords(solder_perm_bits_share0[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j], ConstGarbledCircuit::out_bit_commit0(circuit, exec_permuted_aux_info[curr_head_circuit], j));

        std::copy(ConstGarbledCircuit::out_bit_commit1(circuit, exec_permuted_aux_info[curr_circuit], j),
                  ConstGarbledCircuit::out_bit_commit1(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_perm_bits_share1[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j]);
        XOR_BitCodeWords(solder_perm_bits_share1[solder_out_keys_idx + curr_solder_write_pos * circuit.num_out_wires + j], ConstGarbledCircuit::out_bit_commit1(circuit, exec_permuted_aux_info[curr_head_circuit], j));
      }
    }
  }

  //Send postulated solderings and prove correct using BatchDecommit
  exec_common_tools.chan.Send(solder_keys.GetArray(), solder_keys.size);
  //Send postulated perm bit values and prove correct using BatchDecommit
  exec_common_tools.chan.Send(solder_commit_perm_bits.GetArray(), solder_commit_perm_bits.size);


  CommitSender commit_snd(exec_common_tools, commit_seed_OTs0.GetArray(), commit_seed_OTs1.GetArray());
  commit_snd.BatchDecommit(solder_keys_share0.GetArray(), solder_keys_share1.GetArray(), solder_num_commit_keys);

  BitCommitSender bit_commit_snd(exec_common_tools, commit_seed_OTs0[CODEWORD_BITS], commit_seed_OTs1[CODEWORD_BITS]);
  bit_commit_snd.BatchDecommit(solder_perm_bits_share0.GetArray(), solder_perm_bits_share1.GetArray(), solder_num_base_keys);

  //////////////////////////////Write to Disc/////////////////////////////////

  uint64_t exec_auxdata_write_pos = exec_write_head_auxdata.size * exec_common_tools.exec_id;

  persistent_storage.WriteBuckets(component_type, AUXDATA, exec_buckets_from, exec_num_buckets, exec_write_head_auxdata.GetArray(), exec_auxdata_write_pos, exec_write_head_auxdata.size, bucket_size);
}

void DuploConstructor::ComputeAndSendSolderings(CommonTools& exec_common_tools, std::string& res_component, ComposedCircuit& composed_circuit, uint32_t inp_wire_components_from, uint32_t inp_wire_components_to) {

  uint32_t exec_num_inp_wire_components = inp_wire_components_to - inp_wire_components_from;

  if (exec_num_inp_wire_components == 0) {
    return;
  }

  std::vector<uint32_t> inp_pos;
  std::vector<uint32_t> perm_bit_inp_pos;
  uint32_t exec_num_total_wire_solderings = 0;
  uint32_t exec_num_total_deltas = 0;
  for (int l = 0; l < exec_num_inp_wire_components; ++l) {
    uint32_t curr_component = composed_circuit.num_inp_circuits + inp_wire_components_from + l;

    inp_pos.emplace_back(exec_num_total_wire_solderings + exec_num_total_deltas);
    perm_bit_inp_pos.emplace_back(exec_num_total_wire_solderings);

    std::string inp_wire_component_name(std::get<0>(composed_circuit.circuits[curr_component]));
    Circuit& circuit = string_to_circuit_map[inp_wire_component_name];

    exec_num_total_wire_solderings += circuit.num_inp_wires;
    exec_num_total_deltas += composed_circuit.out_wire_holders[curr_component].size();
  }

  uint32_t exec_num_total_solderings = exec_num_total_wire_solderings + exec_num_total_deltas;

  BYTEArrayVector solder_keys_share0(exec_num_total_solderings, CODEWORD_BYTES);
  BYTEArrayVector solder_keys_share1(exec_num_total_solderings, CODEWORD_BYTES);
  BYTEArrayVector solder_keys(exec_num_total_solderings, CSEC_BYTES);

  BYTEArrayVector solder_perm_bits_share0(exec_num_total_wire_solderings, BIT_CODEWORD_BYTES);
  BYTEArrayVector solder_perm_bits_share1(exec_num_total_wire_solderings, BIT_CODEWORD_BYTES);
  BYTEArrayVector solder_commit_perm_bits(BITS_TO_BYTES(exec_num_total_wire_solderings), 1);

  for (int l = 0; l < exec_num_inp_wire_components; ++l) {
    uint32_t curr_component = composed_circuit.num_inp_circuits + inp_wire_components_from + l;

    std::string inp_wire_component_name(std::get<0>(composed_circuit.circuits[curr_component]));
    uint32_t inp_wire_component_num(std::get<1>(composed_circuit.circuits[curr_component]));
    Circuit& inp_circuit = string_to_circuit_map[inp_wire_component_name];
    BYTEArrayVector inp_wire_component_aux_info;
    persistent_storage.ReadBuckets(inp_wire_component_name, AUXDATA, inp_wire_component_num, 1, inp_wire_component_aux_info);

    //Add all input component values to soldering
    for (int j = 0; j < inp_circuit.num_inp_wires; ++j) {
      XOR_128(solder_keys[inp_pos[l] + j],
              ConstGarbledCircuit::inp_key_commit0(inp_circuit, inp_wire_component_aux_info.GetArray(), j),
              ConstGarbledCircuit::inp_key_commit1(inp_circuit, inp_wire_component_aux_info.GetArray(), j));

      std::copy(ConstGarbledCircuit::inp_key_commit0(inp_circuit, inp_wire_component_aux_info.GetArray(), j),
                ConstGarbledCircuit::inp_key_commit0(inp_circuit, inp_wire_component_aux_info.GetArray(), j + 1),
                solder_keys_share0[inp_pos[l] + j]);

      std::copy(ConstGarbledCircuit::inp_key_commit1(inp_circuit, inp_wire_component_aux_info.GetArray(), j),
                ConstGarbledCircuit::inp_key_commit1(inp_circuit, inp_wire_component_aux_info.GetArray(), j + 1),
                solder_keys_share1[inp_pos[l] + j]);

      XORBit(
        perm_bit_inp_pos[l] + j,
        GetBit(0, ConstGarbledCircuit::inp_bit_commit0(inp_circuit, inp_wire_component_aux_info.GetArray(), j)),
        GetBit(0, ConstGarbledCircuit::inp_bit_commit1(inp_circuit, inp_wire_component_aux_info.GetArray(), j)), solder_commit_perm_bits.GetArray());

      std::copy(ConstGarbledCircuit::inp_bit_commit0(inp_circuit, inp_wire_component_aux_info.GetArray(), j),
                ConstGarbledCircuit::inp_bit_commit0(inp_circuit, inp_wire_component_aux_info.GetArray(), j + 1),
                solder_perm_bits_share0[perm_bit_inp_pos[l] + j]);

      std::copy(ConstGarbledCircuit::inp_bit_commit1(inp_circuit, inp_wire_component_aux_info.GetArray(), j),
                ConstGarbledCircuit::inp_bit_commit1(inp_circuit, inp_wire_component_aux_info.GetArray(), j + 1),
                solder_perm_bits_share1[perm_bit_inp_pos[l] + j]);
    }

    uint32_t curr_inp_wire = 0;
    for (int i = 0; i < composed_circuit.out_wire_holders[curr_component].size(); ++i) {

      //Add delta solderings from input wire component to all delta positions
      XOR_128(solder_keys[inp_pos[l] + inp_circuit.num_inp_wires + i],
              ConstGarbledCircuit::delta_commit0(inp_circuit, inp_wire_component_aux_info.GetArray()),
              ConstGarbledCircuit::delta_commit1(inp_circuit, inp_wire_component_aux_info.GetArray()));

      std::copy(ConstGarbledCircuit::delta_commit0(inp_circuit, inp_wire_component_aux_info.GetArray()),
                ConstGarbledCircuit::delta_commit0(inp_circuit, inp_wire_component_aux_info.GetArray()) + CODEWORD_BYTES,
                solder_keys_share0[inp_pos[l] + inp_circuit.num_inp_wires + i]);

      std::copy(ConstGarbledCircuit::delta_commit1(inp_circuit, inp_wire_component_aux_info.GetArray()),
                ConstGarbledCircuit::delta_commit1(inp_circuit, inp_wire_component_aux_info.GetArray()) + CODEWORD_BYTES,
                solder_keys_share1[inp_pos[l] + inp_circuit.num_inp_wires + i]);

      //Get current circuit information and soldering indices
      std::pair<uint32_t, std::vector<uint32_t>>& out_wire_component_pair = composed_circuit.out_wire_holders[curr_component][i];
      std::pair<std::string, uint32_t> out_wire_component = composed_circuit.circuits[std::get<0>(out_wire_component_pair)];

      std::string out_wire_component_name = std::get<0>(out_wire_component);
      uint32_t out_wire_component_num = std::get<1>(out_wire_component);
      Circuit& out_circuit = string_to_circuit_map[out_wire_component_name];

      //Read current output circuit
      BYTEArrayVector out_wire_component_aux_info;
      persistent_storage.ReadBuckets(out_wire_component_name, AUXDATA, out_wire_component_num, 1, out_wire_component_aux_info);

      //Add the delta soldering information
      XOR_128(solder_keys[inp_pos[l] + inp_circuit.num_inp_wires + i],
              ConstGarbledCircuit::delta_commit0(out_circuit, out_wire_component_aux_info.GetArray()));
      XOR_128(solder_keys[inp_pos[l] + inp_circuit.num_inp_wires + i],
              ConstGarbledCircuit::delta_commit1(out_circuit, out_wire_component_aux_info.GetArray()));

      XOR_CodeWords(solder_keys_share0[inp_pos[l] + inp_circuit.num_inp_wires + i], ConstGarbledCircuit::delta_commit0(out_circuit, out_wire_component_aux_info.GetArray()));
      XOR_CodeWords(solder_keys_share1[inp_pos[l] + inp_circuit.num_inp_wires + i], ConstGarbledCircuit::delta_commit1(out_circuit, out_wire_component_aux_info.GetArray()));


      //Run through the soldering pairs and apply the soldering
      std::vector<uint32_t>& out_wires = std::get<1>(out_wire_component_pair);

      for (int j = 0; j < out_wires.size(); ++j) {

        XOR_128(solder_keys[inp_pos[l] + curr_inp_wire],
                ConstGarbledCircuit::out_key_commit0(out_circuit, out_wire_component_aux_info.GetArray(), out_wires[j]));
        XOR_128(solder_keys[inp_pos[l] + curr_inp_wire],
                ConstGarbledCircuit::out_key_commit1(out_circuit, out_wire_component_aux_info.GetArray(), out_wires[j]));

        XOR_CodeWords(solder_keys_share0[inp_pos[l] + curr_inp_wire], ConstGarbledCircuit::out_key_commit0(out_circuit, out_wire_component_aux_info.GetArray(), out_wires[j]));

        XOR_CodeWords(solder_keys_share1[inp_pos[l] + curr_inp_wire], ConstGarbledCircuit::out_key_commit1(out_circuit, out_wire_component_aux_info.GetArray(), out_wires[j]));

        //Add output perm bit decommits
        XOR_BitCodeWords(solder_perm_bits_share0[perm_bit_inp_pos[l] + curr_inp_wire], ConstGarbledCircuit::out_bit_commit0(out_circuit, out_wire_component_aux_info.GetArray(), out_wires[j]));
        XOR_BitCodeWords(solder_perm_bits_share1[perm_bit_inp_pos[l] + curr_inp_wire], ConstGarbledCircuit::out_bit_commit1(out_circuit, out_wire_component_aux_info.GetArray(), out_wires[j]));

        //XOR output perm bit values
        XORBit(
          perm_bit_inp_pos[l] + curr_inp_wire,
          GetBit(0, ConstGarbledCircuit::out_bit_commit0(out_circuit, out_wire_component_aux_info.GetArray(), out_wires[j])), solder_commit_perm_bits.GetArray());
        XORBit(
          perm_bit_inp_pos[l] + curr_inp_wire,
          GetBit(0, ConstGarbledCircuit::out_bit_commit1(out_circuit, out_wire_component_aux_info.GetArray(), out_wires[j])), solder_commit_perm_bits.GetArray());

        // Check if xor(inp_perm_bit, out_perm_bit) == 1. If it is we flip the soldering
        if (GetBit(perm_bit_inp_pos[l] + curr_inp_wire, solder_commit_perm_bits.GetArray())) {

          XOR_128(solder_keys[inp_pos[l] + curr_inp_wire],
                  ConstGarbledCircuit::delta_commit0(inp_circuit, inp_wire_component_aux_info.GetArray()));
          XOR_128(solder_keys[inp_pos[l] + curr_inp_wire],
                  ConstGarbledCircuit::delta_commit1(inp_circuit, inp_wire_component_aux_info.GetArray()));
          XOR_CodeWords(solder_keys_share0[inp_pos[l] + curr_inp_wire], ConstGarbledCircuit::delta_commit0(inp_circuit, inp_wire_component_aux_info.GetArray()));
          XOR_CodeWords(solder_keys_share1[inp_pos[l] + curr_inp_wire], ConstGarbledCircuit::delta_commit1(inp_circuit, inp_wire_component_aux_info.GetArray()));

        }
        ++curr_inp_wire;
      }
    }
  }

  //Send postulated solderings and prove correct using BatchDecommit
  exec_common_tools.chan.Send(solder_keys.GetArray(), solder_keys.size);

  //Send postulated perm bit values and prove correct using BatchDecommit
  exec_common_tools.chan.Send(solder_commit_perm_bits.GetArray(), solder_commit_perm_bits.size);

  CommitSender commit_snd(exec_common_tools, commit_seed_OTs0.GetArray(), commit_seed_OTs1.GetArray());
  commit_snd.BatchDecommit(solder_keys_share0.GetArray(), solder_keys_share1.GetArray(), exec_num_total_solderings);

  BitCommitSender bit_commit_snd(exec_common_tools, commit_seed_OTs0[CODEWORD_BITS], commit_seed_OTs1[CODEWORD_BITS]);
  bit_commit_snd.BatchDecommit(solder_perm_bits_share0.GetArray(), solder_perm_bits_share1.GetArray(), exec_num_total_wire_solderings);
}

void DuploConstructor::CommitAuthAndCutAndChoose(CommonTools & exec_common_tools, uint32_t exec_num_auths, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_auths_from, uint32_t exec_eval_auths_to, std::vector<BYTEArrayVector>& aux_auth_data, BYTEArrayVector & aux_auth_delta_data, std::tuple<std::mutex&, std::condition_variable&, bool&>& delta_signal) {

  CommitSender commit_snd(exec_common_tools, commit_seed_OTs0.GetArray(), commit_seed_OTs1.GetArray());

  //If this is exec_id == 0 we produce one delta commitment.
  uint32_t num_commit_keys;
  if (exec_common_tools.exec_id == 0) {
    num_commit_keys = exec_num_auths + 1;
  } else {
    num_commit_keys = exec_num_auths;
  }

  BYTEArrayVector commit_keys_share0(num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector commit_keys_share1(num_commit_keys, CODEWORD_BYTES);

  //Commit to the input/output wires and Deltas of all garbled circuits.
  commit_snd.Commit(num_commit_keys, commit_keys_share0, commit_keys_share1, exec_prg_counter, num_commit_keys);

  std::condition_variable& delta_updated_cond_val = std::get<1>(delta_signal);
  bool& delta_updated = std::get<2>(delta_signal);

  if (exec_common_tools.exec_id == 0) {
    std::copy(commit_keys_share0[num_commit_keys - 1], commit_keys_share0[num_commit_keys], aux_auth_delta_data[0]);
    std::copy(commit_keys_share1[num_commit_keys - 1], commit_keys_share1[num_commit_keys], aux_auth_delta_data[1]);
    delta_updated = true;
    delta_updated_cond_val.notify_all();
  } else {
    std::mutex& delta_updated_mutex = std::get<0>(delta_signal);
    unique_lock<mutex> lock(delta_updated_mutex);
    while (!delta_updated) {
      delta_updated_cond_val.wait(lock);
    }
  }

  uint32_t H_0_idx = 0;
  uint32_t H_1_idx = exec_num_auths;

  BYTEArrayVector auths(2 * exec_num_auths, CSEC_BYTES);

  uint8_t current_key[CSEC_BYTES];
  uint8_t delta[CSEC_BYTES];
  XOR_128(delta, aux_auth_delta_data[0], aux_auth_delta_data[1]);

  GarblingHandler gh;
  uint32_t global_auth_idx;
  for (int i = 0; i < exec_num_auths; ++i) {
    global_auth_idx = exec_eval_auths_from + i;

    XOR_128(current_key, commit_keys_share0[i], commit_keys_share1[i]);

    Auth(current_key, delta, global_auth_idx, auths[H_0_idx + i], auths[H_1_idx + i], gh.key_schedule);

  }

  //Send wire authenticators
  exec_common_tools.chan.Send(auths.GetArray(), auths.size);

  ///////////////////////// CUT-AND-CHOOSE /////////////////////////

  //Receive challenge seed
  uint8_t cnc_seed[CSEC_BYTES];
  exec_common_tools.chan.ReceiveBlocking(cnc_seed, CSEC_BYTES);

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

  //Arrays for holding the decommit shares of the decommited keys
  BYTEArrayVector cnc_keys_share0(cnc_num_auths, CODEWORD_BYTES);
  BYTEArrayVector cnc_keys_share1(cnc_num_auths, CODEWORD_BYTES);
  BYTEArrayVector cnc_keys(cnc_num_auths, CSEC_BYTES);

  uint32_t current_check_auth_idx = 0;
  uint32_t current_eval_auth_idx = exec_eval_auths_from;
  bool completed_eval_copy = false;
  for (int i = 0; i < exec_num_auths; ++i) {
    if (GetBit(i, cnc_check_auths.data())) { //Checked auths
      //Add key shares
      std::copy(commit_keys_share0[i], commit_keys_share0[(i + 1)], cnc_keys_share0[current_check_auth_idx]);
      std::copy(commit_keys_share1[i], commit_keys_share1[(i + 1)], cnc_keys_share1[current_check_auth_idx]);

      if (GetBit(current_check_auth_idx, cnc_check_inputs.data())) {
        XOR_CodeWords(cnc_keys_share0[current_check_auth_idx], aux_auth_delta_data[0]);
        XOR_CodeWords(cnc_keys_share1[current_check_auth_idx], aux_auth_delta_data[1]);
      }

      //Add key
      XOR_128(cnc_keys[current_check_auth_idx], cnc_keys_share0[current_check_auth_idx], cnc_keys_share1[current_check_auth_idx]);

      ++current_check_auth_idx;
    } else if (current_eval_auth_idx < exec_eval_auths_to) {

      //Copy key info
      std::copy(commit_keys_share0[i], commit_keys_share0[(i + 1)], aux_auth_data[current_eval_auth_idx][0]);
      std::copy(commit_keys_share1[i], commit_keys_share1[(i + 1)], aux_auth_data[current_eval_auth_idx][1]);

      ++current_eval_auth_idx;
    } else {
      completed_eval_copy = true;
    }
  }

  if (!completed_eval_copy) {
    std::cout << "Problem. Not enough eval auths! Params should be set so this never occurs" << std::endl;
  }

  //BatchDecommit the cut-and-choose input and output keys. Needs to be done after BatchDecommit of perm bit values.
  exec_common_tools.chan.Send(cnc_keys.GetArray(), cnc_keys.size);
  commit_snd.BatchDecommit(cnc_keys_share0.GetArray(), cnc_keys_share1.GetArray(), cnc_num_auths);
}

void DuploConstructor::BucketAllAuths(CommonTools & exec_common_tools, uint32_t auth_size, std::vector<uint32_t>& permuted_eval_ids_inv, std::vector<int>& session_circuit_buckets_from, std::vector<int>& session_circuit_buckets_to, std::vector<BYTEArrayVector>& aux_auth_data, BYTEArrayVector & aux_auth_delta_data, std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t input_components_from, uint32_t input_components_to, std::vector<uint32_t>& input_components_auth_start_pos) {

  uint32_t num_sessions = session_circuit_buckets_from.size();

  uint32_t total_num_solderings = 0;
  for (int l = 0; l < num_sessions; ++l) {
    Circuit& session_circuit = std::get<1>(circuit_info[l]);
    uint32_t session_num_circuit_buckets = std::get<2>(circuit_info[l]);
    uint32_t exec_session_num_circuit_buckets = session_circuit_buckets_to[l] - session_circuit_buckets_from[l];

    total_num_solderings += exec_session_num_circuit_buckets * (auth_size * session_circuit.num_out_wires + 1);
  }

  //Add the info from the input_components to total_num_solderings
  uint32_t exec_num_input_components = input_components_to - input_components_from;
  for (int l = 0; l < exec_num_input_components; ++l) {
    uint32_t curr_component = input_components_from + l;
    std::string input_component_name = std::get<0>(input_components[curr_component]);
    Circuit& input_component = string_to_circuit_map[input_component_name];

    total_num_solderings += (auth_size * input_component.num_inp_wires + 1);
  }

  //For decomitting later on
  BYTEArrayVector solder_keys_share0(total_num_solderings, CODEWORD_BYTES);
  BYTEArrayVector solder_keys_share1(total_num_solderings, CODEWORD_BYTES);
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
      XOR_128(solder_keys[curr_solder_write_pos],
              ConstGarbledCircuit::delta_commit0(session_circuit, curr_session_aux_info[i]),
              ConstGarbledCircuit::delta_commit1(session_circuit, curr_session_aux_info[i]));
      XOR_128(solder_keys[curr_solder_write_pos], aux_auth_delta_data[0]);
      XOR_128(solder_keys[curr_solder_write_pos], aux_auth_delta_data[1]);

      std::copy(ConstGarbledCircuit::delta_commit0(session_circuit, curr_session_aux_info[i]),
                ConstGarbledCircuit::delta_commit0(session_circuit, curr_session_aux_info[i]) + CODEWORD_BYTES,
                solder_keys_share0[curr_solder_write_pos]);
      XOR_CodeWords(solder_keys_share0[curr_solder_write_pos], aux_auth_delta_data[0]);

      std::copy(ConstGarbledCircuit::delta_commit1(session_circuit, curr_session_aux_info[i]),
                ConstGarbledCircuit::delta_commit1(session_circuit, curr_session_aux_info[i])  + CODEWORD_BYTES,
                solder_keys_share1[curr_solder_write_pos]);
      XOR_CodeWords(solder_keys_share1[curr_solder_write_pos], aux_auth_delta_data[1]);

      ++curr_solder_write_pos;

      //Copy all bucket_size*session_circuit.num_out_wires solderings
      for (int j = 0; j < session_circuit.num_out_wires; ++j) {
        for (int a = 0; a < auth_size; ++a) {
          uint32_t perm_auth_idx = permuted_eval_ids_inv[(curr_session_bucket_idx * session_circuit.num_out_wires + j) * auth_size + a];
          BYTEArrayVector& current_aux_auth_data = aux_auth_data[perm_auth_idx];

          XOR_128(solder_keys[curr_solder_write_pos],
                  ConstGarbledCircuit::out_key_commit0(session_circuit, curr_session_aux_info[i], j),
                  ConstGarbledCircuit::out_key_commit1(session_circuit, curr_session_aux_info[i], j));
          XOR_128(solder_keys[curr_solder_write_pos], current_aux_auth_data[0]);
          XOR_128(solder_keys[curr_solder_write_pos], current_aux_auth_data[1]);

          std::copy(ConstGarbledCircuit::out_key_commit0(session_circuit, curr_session_aux_info[i], j),
                    ConstGarbledCircuit::out_key_commit0(session_circuit, curr_session_aux_info[i], j + 1),
                    solder_keys_share0[curr_solder_write_pos]);
          XOR_CodeWords(solder_keys_share0[curr_solder_write_pos], current_aux_auth_data[0]);

          std::copy(ConstGarbledCircuit::out_key_commit1(session_circuit, curr_session_aux_info[i], j),
                    ConstGarbledCircuit::out_key_commit1(session_circuit, curr_session_aux_info[i], j + 1),
                    solder_keys_share1[curr_solder_write_pos]);
          XOR_CodeWords(solder_keys_share1[curr_solder_write_pos], current_aux_auth_data[1]);

          ++curr_solder_write_pos;
        }
      }
    }
  }

  for (int l = 0; l < exec_num_input_components; ++l) {
    uint32_t curr_component = input_components_from + l;
    std::string input_component_name = std::get<0>(input_components[curr_component]);
    uint32_t input_component_num = std::get<1>(input_components[curr_component]);
    Circuit& input_component = string_to_circuit_map[input_component_name];


    //Read all session circuit info
    BYTEArrayVector curr_circuit_aux_info;
    persistent_storage.ReadBuckets(input_component_name, AUXDATA, input_component_num, 1, curr_circuit_aux_info);

    //Copy Delta soldering
    XOR_128(solder_keys[curr_solder_write_pos],
            ConstGarbledCircuit::delta_commit0(input_component, curr_circuit_aux_info.GetArray()),
            ConstGarbledCircuit::delta_commit1(input_component, curr_circuit_aux_info.GetArray()));
    XOR_128(solder_keys[curr_solder_write_pos], aux_auth_delta_data[0]);
    XOR_128(solder_keys[curr_solder_write_pos], aux_auth_delta_data[1]);

    std::copy(ConstGarbledCircuit::delta_commit0(input_component, curr_circuit_aux_info.GetArray()),
              ConstGarbledCircuit::delta_commit0(input_component, curr_circuit_aux_info.GetArray() + CODEWORD_BYTES),
              solder_keys_share0[curr_solder_write_pos]);
    XOR_CodeWords(solder_keys_share0[curr_solder_write_pos], aux_auth_delta_data[0]);

    std::copy(ConstGarbledCircuit::delta_commit1(input_component, curr_circuit_aux_info.GetArray()),
              ConstGarbledCircuit::delta_commit1(input_component, curr_circuit_aux_info.GetArray()) + CODEWORD_BYTES,
              solder_keys_share1[curr_solder_write_pos]);
    XOR_CodeWords(solder_keys_share1[curr_solder_write_pos], aux_auth_delta_data[1]);

    ++curr_solder_write_pos;

    for (int j = 0; j < input_component.num_inp_wires; ++j) {
      for (int a = 0; a < auth_size; ++a) {
        uint32_t perm_auth_idx = permuted_eval_ids_inv[input_components_auth_start_pos[curr_component] + j * auth_size + a];
        BYTEArrayVector& current_aux_auth_data = aux_auth_data[perm_auth_idx];

        XOR_128(solder_keys[curr_solder_write_pos],
                ConstGarbledCircuit::inp_key_commit0(input_component, curr_circuit_aux_info.GetArray(), j),
                ConstGarbledCircuit::inp_key_commit1(input_component, curr_circuit_aux_info.GetArray(), j));
        XOR_128(solder_keys[curr_solder_write_pos], current_aux_auth_data[0]);
        XOR_128(solder_keys[curr_solder_write_pos], current_aux_auth_data[1]);

        std::copy(ConstGarbledCircuit::inp_key_commit0(input_component, curr_circuit_aux_info.GetArray(), j),
                  ConstGarbledCircuit::inp_key_commit0(input_component, curr_circuit_aux_info.GetArray(), j + 1),
                  solder_keys_share0[curr_solder_write_pos]);
        XOR_CodeWords(solder_keys_share0[curr_solder_write_pos], current_aux_auth_data[0]);

        std::copy(ConstGarbledCircuit::inp_key_commit1(input_component, curr_circuit_aux_info.GetArray(), j),
                  ConstGarbledCircuit::inp_key_commit1(input_component, curr_circuit_aux_info.GetArray(), j + 1),
                  solder_keys_share1[curr_solder_write_pos]);
        XOR_CodeWords(solder_keys_share1[curr_solder_write_pos], current_aux_auth_data[1]);

        ++curr_solder_write_pos;
      }
    }
  }

  CommitSender commit_snd(exec_common_tools, commit_seed_OTs0.GetArray(), commit_seed_OTs1.GetArray());

//Send postulated solderings and prove correct using BatchDecommit
  exec_common_tools.chan.Send(solder_keys.GetArray(), solder_keys.size);

  commit_snd.BatchDecommit(solder_keys_share0.GetArray(), solder_keys_share1.GetArray(), total_num_solderings);
}

void DuploConstructor::PrepareInputBuckets(std::vector<std::pair<std::string, uint32_t>>& input_components, uint num_parallel_execs) {
  //Find out how many input wires
  uint64_t num_total_const_inputs = 0;
  for (int i = 0; i < input_components.size(); ++i) {
    std::string component_name = std::get<0>(input_components[i]);
    Circuit& circuit = string_to_circuit_map[component_name];
    num_total_const_inputs += circuit.num_const_inp_wires;
  }

  if (num_total_const_inputs == 0) {
    return;
  }

  //Compute parameters
  long double check_factor;
  uint32_t bucket_size;
  bool negate_check_factor;

  auto t_param_start = GET_TIME();
  FindBestMajorityParams(num_total_const_inputs, bucket_size, check_factor, negate_check_factor, 1);
  auto t_param_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(t_param_start, t_param_end, input_components.size(), "FindMajParam");

  double cnc_check_prob;
  if (negate_check_factor) {
    cnc_check_prob = 1 - (1 / pow(2, check_factor));
  } else {
    cnc_check_prob = (1 / pow(2, check_factor));
  }

  std::cout << "bucket_size=" << bucket_size << ", " << "cnc_check_prob=" << cnc_check_prob << std::endl;
#endif

  auto inp_bucket_commit_cnc_begin = GET_TIME();

  uint32_t num_buckets = num_total_const_inputs;
  uint32_t num_eval_circuits = bucket_size * num_buckets;

  std::vector<std::future<void>> execs_finished(num_parallel_execs);

  std::vector<int> eval_circuits_from, eval_circuits_to, inp_buckets_from, inp_buckets_to;

  PartitionBufferFixedNum(eval_circuits_from, eval_circuits_to, num_parallel_execs, num_eval_circuits);
  PartitionBufferFixedNum(inp_buckets_from, inp_buckets_to, num_parallel_execs, input_components.size());

  std::vector<ConstGarbledCircuit> aux_garbled_circuits_data(num_eval_circuits, ConstGarbledCircuit(inp_bucket_circuit, 0));

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    uint64_t exec_prg_counter = curr_prg_counter;
    curr_prg_counter += FIXED_PRG_INC_NUMBER;

    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &aux_garbled_circuits_data, &eval_circuits_from, &eval_circuits_to, exec_id, exec_prg_counter, check_factor, negate_check_factor] (int id) {

      uint32_t exec_num_buckets = eval_circuits_to[exec_id] - eval_circuits_from[exec_id];

      float slack_val, repl_factor;
      ComputeCheckFraction(check_factor, exec_num_buckets, slack_val, repl_factor, negate_check_factor);

      uint32_t exec_num_total_circuits = ceil(repl_factor * exec_num_buckets);

      InpBucketCommitAndCutAndChoose(exec_common_tools, inp_bucket_circuit, exec_num_total_circuits, exec_prg_counter, check_factor, negate_check_factor, eval_circuits_from[exec_id], eval_circuits_to[exec_id], aux_garbled_circuits_data);
    });
  }

  for (std::future<void>& r : execs_finished) {
    r.wait();
  }

  //Do not add this circuit to circuit_info
  // circuit_info.emplace_back(std::make_tuple(CONST_INP_BUCKET_PREFIX, inp_bucket_circuit, num_buckets));

  auto inp_bucket_commit_cnc_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(inp_bucket_commit_cnc_begin, inp_bucket_commit_cnc_end, input_components.size(), "InpBucketCommitCNC");
#endif

  uint64_t auxdata_bytes = ConstGarbledCircuit::AuxDataSize(inp_bucket_circuit) * num_buckets;

  uint8_t bucket_seed[CSEC_BYTES];
  common_tools.chan.ReceiveBlocking(bucket_seed, CSEC_BYTES);

  std::vector<uint32_t> permuted_eval_ids(num_eval_circuits);
  std::vector<uint32_t> permuted_eval_ids_inv(num_eval_circuits);
  std::iota(std::begin(permuted_eval_ids), std::end(permuted_eval_ids), 0);
  PermuteArray(permuted_eval_ids.data(), num_eval_circuits, bucket_seed);
  for (int i = 0; i < num_eval_circuits; ++i) {
    permuted_eval_ids_inv[permuted_eval_ids[i]] = i;
  }

  auto inp_bucketing_begin = GET_TIME();

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {
    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &input_components, &exec_common_tools, &aux_garbled_circuits_data, &inp_buckets_from, &inp_buckets_to, exec_id, bucket_size, &permuted_eval_ids_inv] (int id) {

      InpBucketSendSolderings(input_components, exec_common_tools, inp_bucket_circuit, bucket_size, permuted_eval_ids_inv, inp_buckets_from[exec_id], inp_buckets_to[exec_id], aux_garbled_circuits_data);
    });
  }

  for (std::future<void>& r : execs_finished) {
    r.wait();
  }

  auto inp_bucketing_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(inp_bucketing_begin, inp_bucketing_end, input_components.size(), "InputBucketing");
#endif
}

void DuploConstructor::PreprocessEvalInputOTs(std::vector<std::pair<std::string, uint32_t>>& input_components) {

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
  uint8_t delta[CSEC_BYTES] = {0};
  BYTEArrayVector input_masks(num_ots, CSEC_BYTES);
  ot_snd.Send(num_ots, input_masks.GetArray(), delta);

  //Run Random Commit
  uint32_t num_commits = num_ots + 1;
  BYTEArrayVector commit_keys_share0(num_commits, CODEWORD_BYTES);
  BYTEArrayVector commit_keys_share1(num_commits, CODEWORD_BYTES);

  CommitSender commit_snd(common_tools, commit_seed_OTs0.GetArray(), commit_seed_OTs1.GetArray());
  uint64_t exec_prg_counter = curr_prg_counter;
  curr_prg_counter += FIXED_PRG_INC_NUMBER;
  commit_snd.Commit(num_commits, commit_keys_share0, commit_keys_share1, exec_prg_counter);

  //Run chosen commit
  BYTEArrayVector input_mask_corrections(num_commits, CSEC_BYTES);
  for (int i = 0; i < num_ots; ++i) {
    XOR_128(input_mask_corrections[i], commit_keys_share0[i], commit_keys_share1[i]);
    XOR_128(input_mask_corrections[i], input_masks[i]);
  }
  XOR_128(input_mask_corrections[num_ots], commit_keys_share0[num_ots], commit_keys_share1[num_ots]);
  XOR_128(input_mask_corrections[num_ots], delta);

  common_tools.chan.Send(input_mask_corrections.GetArray(), input_mask_corrections.size);


  //////////////////////////////////////CNC////////////////////////////////////

  //Receive values from receiver and check that they are valid OTs. In the same loop we also build the decommit information.
  std::vector<uint8_t> cnc_ot_values(SSEC * CSEC_BYTES + SSEC_BYTES);
  common_tools.chan.ReceiveBlocking(cnc_ot_values.data(),  SSEC * CSEC_BYTES + SSEC_BYTES);
  uint8_t* ot_delta_cnc_choices = cnc_ot_values.data() + SSEC * CSEC_BYTES;

  uint8_t correct_ot_value[CSEC_BYTES];
  BYTEArrayVector chosen_decommit_shares0(SSEC, CODEWORD_BYTES);
  BYTEArrayVector chosen_decommit_shares1(SSEC, CODEWORD_BYTES);

  for (int i = 0; i < SSEC; ++i) {
    std::copy(commit_keys_share0[num_total_eval_inputs + i], commit_keys_share0[num_total_eval_inputs + i + 1], chosen_decommit_shares0[i]);
    std::copy(commit_keys_share1[num_total_eval_inputs + i], commit_keys_share1[num_total_eval_inputs + i + 1], chosen_decommit_shares1[i]);
    std::copy(input_masks[num_total_eval_inputs + i], input_masks[num_total_eval_inputs + i + 1], correct_ot_value);

    if (GetBit(i, ot_delta_cnc_choices)) {

      XOR_CodeWords(chosen_decommit_shares0[i], commit_keys_share0[num_ots]);
      XOR_CodeWords(chosen_decommit_shares1[i], commit_keys_share1[num_ots]);
      XOR_128(correct_ot_value, delta);
    }

    if (!equal(correct_ot_value, correct_ot_value + CSEC_BYTES,  cnc_ot_values.data() + i * CSEC_BYTES)) {
      std::cout << "Receiver cheating. Trying to make us open to wrong OT!" << std::endl;
      throw std::runtime_error("Receiver cheating. Trying to make us open to wrong OT!");
    }
  }

  //As receiver sent correct input masks, we now decommit to the same values. Will prove that sender indeed comitted to Delta
  common_tools.chan.Send(chosen_decommit_shares0.GetArray(), chosen_decommit_shares0.size);
  common_tools.chan.Send(chosen_decommit_shares1.GetArray(), chosen_decommit_shares1.size);

  //Update global input wire counter
  curr_num_ready_inputs = num_total_eval_inputs;

  //Write data to disc
  BYTEArrayVector shares(num_total_eval_inputs, 2 * CODEWORD_BYTES);
  BYTEArrayVector delta_shares(2, CODEWORD_BYTES);

  for (int i = 0; i < num_total_eval_inputs; ++i) {
    std::copy(commit_keys_share0[i], commit_keys_share0[i + 1], shares[i]);
    std::copy(commit_keys_share1[i], commit_keys_share1[i + 1], shares[i] + CODEWORD_BYTES);
  }
  std::copy(commit_keys_share0[num_ots], commit_keys_share0[num_ots + 1], delta_shares[0]);
  std::copy(commit_keys_share1[num_ots], commit_keys_share1[num_ots + 1], delta_shares[1]);

  persistent_storage.PrepareFile(CONST_PREPROCESS_PREFIX, INPUT_MASKS_AUXDATA, shares.size);
  persistent_storage.PrepareFile(CONST_PREPROCESS_PREFIX, INPUT_MASKS_DELTA_AUXDATA, delta_shares.size);

  persistent_storage.WriteBuckets(CONST_PREPROCESS_PREFIX, INPUT_MASKS_AUXDATA, 0, num_total_eval_inputs, shares.GetArray(), 0, shares.size, 1);

  persistent_storage.WriteBuckets(CONST_PREPROCESS_PREFIX, INPUT_MASKS_DELTA_AUXDATA, 0, 2, delta_shares.GetArray(), 0, delta_shares.size, 1);

  auto preprocess_inputs_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(preprocess_inputs_begin, preprocess_inputs_end, num_components, "PreprocessEvalInputOTs");
#endif
}

void DuploConstructor::DecommitEvalInputPermBits(CommonTools & exec_common_tools, std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t components_from, uint32_t components_to) {

  // uint32_t num_components = input_components.size();
  uint32_t exec_num_components = components_to - components_from;

  // Read inp perm bits corresponding to components
  std::vector<uint32_t> eval_inp_sizes, const_inp_sizes, eval_inp_pos;
  uint32_t num_total_eval_inputs = 0;
  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = components_from + i;
    std::string component_name = std::get<0>(input_components[curr_component]);
    uint32_t component_num = std::get<1>(input_components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];

    eval_inp_pos.emplace_back(num_total_eval_inputs);
    num_total_eval_inputs += circuit.num_eval_inp_wires;

    eval_inp_sizes.emplace_back(circuit.num_eval_inp_wires);
    const_inp_sizes.emplace_back(circuit.num_const_inp_wires);
  }

  if (num_total_eval_inputs < 1) {
    return;
  }

  BYTEArrayVector b_share0(num_total_eval_inputs, BIT_CODEWORD_BYTES);
  BYTEArrayVector b_share1(num_total_eval_inputs, BIT_CODEWORD_BYTES);
  BYTEArrayVector b(BITS_TO_BYTES(num_total_eval_inputs), 1);

  uint32_t inc_pos = 0;
  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = components_from + i;
    std::string component_name = std::get<0>(input_components[curr_component]);
    uint32_t component_num = std::get<1>(input_components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];

    BYTEArrayVector component_aux_data;
    persistent_storage.ReadBuckets(component_name, AUXDATA, component_num, 1, component_aux_data);

    for (int j = 0; j < eval_inp_sizes[i]; ++j) {
      std::copy(ConstGarbledCircuit::inp_bit_commit0(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j),
                ConstGarbledCircuit::inp_bit_commit0(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j + 1),
                b_share0[eval_inp_pos[i] + j]);
      std::copy(ConstGarbledCircuit::inp_bit_commit1(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j),
                ConstGarbledCircuit::inp_bit_commit1(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j + 1),
                b_share1[eval_inp_pos[i] + j]);

      XORBit(inc_pos + j, GetBit(0, ConstGarbledCircuit::inp_bit_commit0(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j)),
             GetBit(0, ConstGarbledCircuit::inp_bit_commit1(circuit, component_aux_data.GetArray(), const_inp_sizes[i] + j)),
             b.GetArray());
    }
    inc_pos += eval_inp_sizes[i];
  }
  //Send postulated perm bit values and prove correct using BatchDecommit
  exec_common_tools.chan.Send(b.GetArray(), b.size);

  BitCommitSender bit_commit_snd(exec_common_tools, commit_seed_OTs0[CODEWORD_BITS], commit_seed_OTs1[CODEWORD_BITS]);
  bit_commit_snd.BatchDecommit(b_share0.GetArray(), b_share1.GetArray(), num_total_eval_inputs);
}

void DuploConstructor::DecommitOutPermBits(CommonTools & exec_common_tools, std::vector<std::pair<std::string, uint32_t>>& output_components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& output_decodings) {

  uint32_t exec_num_components = components_to - components_from;

  // Read inp perm bits corresponding to components
  uint32_t num_eval_total_outputs = 0;
  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = components_from + i;
    std::string component_name = std::get<0>(output_components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];
    num_eval_total_outputs += circuit.num_eval_out_wires;
  }

  BYTEArrayVector exec_res_share0(num_eval_total_outputs, BIT_CODEWORD_BYTES);
  BYTEArrayVector exec_res_share1(num_eval_total_outputs, BIT_CODEWORD_BYTES);
  BYTEArrayVector exec_res(BITS_TO_BYTES(num_eval_total_outputs), 1);

  uint32_t eval_inc_pos = 0;
  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = components_from + i;
    std::string component_name = std::get<0>(output_components[curr_component]);
    uint32_t component_num = std::get<1>(output_components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];

    BYTEArrayVector component_aux_data;
    persistent_storage.ReadBuckets(component_name, AUXDATA, component_num, 1, component_aux_data);

    output_decodings.emplace_back(BYTEArrayVector(BITS_TO_BYTES(circuit.num_const_out_wires), 1));
    for (int j = 0; j < circuit.num_out_wires; ++j) {
      if (j < circuit.const_out_wires_stop) {
        XORBit(j,
               GetBit(0, ConstGarbledCircuit::out_bit_commit0(circuit, component_aux_data.GetArray(), j)),
               GetBit(0, ConstGarbledCircuit::out_bit_commit1(circuit, component_aux_data.GetArray(), j)),
               output_decodings[i].GetArray());
      }

      if ((j >= circuit.eval_out_wires_start) &&
          (j < circuit.eval_out_wires_stop)) {

        uint32_t curr_bit_pos = eval_inc_pos + j - circuit.eval_out_wires_start;
        std::copy(ConstGarbledCircuit::out_bit_commit0(circuit, component_aux_data.GetArray(), j),
                  ConstGarbledCircuit::out_bit_commit0(circuit, component_aux_data.GetArray(), j + 1),
                  exec_res_share0[curr_bit_pos]);
        std::copy(ConstGarbledCircuit::out_bit_commit1(circuit, component_aux_data.GetArray(), j),
                  ConstGarbledCircuit::out_bit_commit1(circuit, component_aux_data.GetArray(), j + 1),
                  exec_res_share1[curr_bit_pos]);

        XORBit(curr_bit_pos,
               GetBit(0, ConstGarbledCircuit::out_bit_commit0(circuit, component_aux_data.GetArray(), j)),
               GetBit(0, ConstGarbledCircuit::out_bit_commit1(circuit, component_aux_data.GetArray(), j)),
               exec_res.GetArray());
      }
    }
    eval_inc_pos += circuit.num_eval_out_wires;
  }
  //Send postulated perm bit values and prove correct using BatchDecommit
  exec_common_tools.chan.Send(exec_res.GetArray(), exec_res.size);

  BitCommitSender bit_commit_snd(exec_common_tools, commit_seed_OTs0[CODEWORD_BITS], commit_seed_OTs1[CODEWORD_BITS]);
  bit_commit_snd.BatchDecommit(exec_res_share0.GetArray(), exec_res_share1.GetArray(), num_eval_total_outputs);
}

void DuploConstructor::InpBucketCommitAndCutAndChoose(CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_num_total_garbled, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_circuits_from, uint32_t exec_eval_circuits_to, std::vector<ConstGarbledCircuit>& aux_garbled_circuits_data) {

  uint32_t num_inp_keys, num_out_keys, num_deltas, num_commit_keys, num_base_keys, inp_keys_idx, out_keys_idx, deltas_idx;
  ComputeIndices(exec_num_total_garbled, circuit, num_inp_keys, num_out_keys, num_deltas, num_commit_keys, num_base_keys, inp_keys_idx, out_keys_idx, deltas_idx);

  CommitSender commit_snd(exec_common_tools, commit_seed_OTs0.GetArray(), commit_seed_OTs1.GetArray());
  BitCommitSender bit_commit_snd(exec_common_tools, commit_seed_OTs0[CODEWORD_BITS], commit_seed_OTs1[CODEWORD_BITS]);

  BYTEArrayVector commit_keys_share0(num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector commit_keys_share1(num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector commit_perm_bits_share0(num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector commit_perm_bits_share1(num_base_keys, BIT_CODEWORD_BYTES);

  //Commit to the input/output wires and Deltas of all garbled circuits.
  commit_snd.Commit(num_commit_keys, commit_keys_share0, commit_keys_share1, exec_prg_counter, deltas_idx);
  //Commit to perm bits
  bit_commit_snd.Commit(num_base_keys, commit_perm_bits_share0, commit_perm_bits_share1, exec_prg_counter);

  //Buffers
  uint8_t delta[CSEC_BYTES];

  GarblingHandler gh;
  std::vector<ConstGarbledCircuit> garbled_circuits(exec_num_total_garbled, ConstGarbledCircuit(circuit));

  BYTEArrayVector inp_wire_commit_corrections(num_inp_keys, CSEC_BYTES);

  //Do all HASHING of keys
  for (int i = 0; i < exec_num_total_garbled; ++i) {
    //Compute the delta used for this circuit
    XOR_128(delta, commit_keys_share0[deltas_idx + i], commit_keys_share1[deltas_idx + i]);
    gh.GarbleInpBucket(inp_wire_commit_corrections[i], delta, 0);

    XOR_128(inp_wire_commit_corrections[i], commit_keys_share0[inp_keys_idx + i]);
    XOR_128(inp_wire_commit_corrections[i], commit_keys_share1[inp_keys_idx + i]);

    if (GetBit(0, commit_perm_bits_share0[inp_keys_idx + i]) ^ GetBit(0, commit_perm_bits_share1[inp_keys_idx + i])) {
      XOR_128(inp_wire_commit_corrections[i], delta);
    }
  }

  //Send output keys commit corrections and hashes of tables. Thereby "commits" constructor to the tables
  exec_common_tools.chan.Send(inp_wire_commit_corrections.GetArray(), inp_wire_commit_corrections.size);

///////////////////////// CUT-AND-CHOOSE /////////////////////////

//Receive challenge seed
  uint8_t cnc_seed[CSEC_BYTES];
  exec_common_tools.chan.ReceiveBlocking(cnc_seed, CSEC_BYTES);

//Select challenge circuits based on cnc_seed
  uint32_t num_bytes_exec_num_total_garbled = BITS_TO_BYTES(exec_num_total_garbled);
  std::vector<uint8_t> cnc_check_circuits(num_bytes_exec_num_total_garbled);
  PRNG cnc_rand;
  cnc_rand.SetSeed(cnc_seed);

  WeightedRandomString(cnc_check_circuits.data(), check_factor, num_bytes_exec_num_total_garbled, cnc_rand, negate_check_factor);
  int num_checked_circuits = countSetBits(cnc_check_circuits.data(), 0, exec_num_total_garbled - 1);

//Compute indices for convenient indexing
  uint32_t cnc_num_inp_keys, cnc_num_out_keys, cnc_num_deltas, cnc_num_commit_keys, cnc_num_base_keys, cnc_inp_keys_idx, cnc_out_keys_idx, cnc_deltas_idx;
  ComputeIndices(num_checked_circuits, circuit, cnc_num_inp_keys, cnc_num_out_keys, cnc_num_deltas, cnc_num_commit_keys, cnc_num_base_keys, cnc_inp_keys_idx, cnc_out_keys_idx, cnc_deltas_idx);

//Arrays for holding the decommit shares of the decommited keys
  BYTEArrayVector cnc_keys_share0(cnc_num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector cnc_keys_share1(cnc_num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector cnc_keys(cnc_num_commit_keys, CSEC_BYTES);

//Arrays for holding the decommit shares of the decommit perm bits
  BYTEArrayVector cnc_perm_bits_share0(cnc_num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector cnc_perm_bits_share1(cnc_num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector cnc_commit_perm_bits(BITS_TO_BYTES(cnc_num_base_keys), 1);

  uint32_t current_check_circuit_idx = 0;
  uint32_t current_eval_circuit_idx = exec_eval_circuits_from;
  bool completed_eval_copy = false;
  for (int i = 0; i < exec_num_total_garbled; ++i) {
    if (GetBit(i, cnc_check_circuits.data())) { //Checked circuit

      //Add delta
      std::copy(commit_keys_share0[deltas_idx + i], commit_keys_share0[deltas_idx + (i + 1)], cnc_keys_share0[cnc_deltas_idx + current_check_circuit_idx]);
      std::copy(commit_keys_share1[deltas_idx + i], commit_keys_share1[deltas_idx + (i + 1)], cnc_keys_share1[cnc_deltas_idx + current_check_circuit_idx]);

      //Compute the delta value
      XOR_128(cnc_keys[cnc_deltas_idx + current_check_circuit_idx], cnc_keys_share0[cnc_deltas_idx + current_check_circuit_idx], cnc_keys_share1[cnc_deltas_idx + current_check_circuit_idx]);

      //Add inputs
      std::copy(commit_keys_share0[inp_keys_idx + i],
                commit_keys_share0[inp_keys_idx + (i + 1)],
                cnc_keys_share0[cnc_inp_keys_idx + current_check_circuit_idx]);
      std::copy(commit_keys_share1[inp_keys_idx + i],
                commit_keys_share1[inp_keys_idx + (i + 1)],
                cnc_keys_share1[cnc_inp_keys_idx + current_check_circuit_idx]);

      XORBit(
        cnc_inp_keys_idx + current_check_circuit_idx,
        GetBit(0, commit_perm_bits_share0[inp_keys_idx + i]),
        GetBit(0, commit_perm_bits_share1[inp_keys_idx + i]), cnc_commit_perm_bits.GetArray());

      //Flip the key and decommit values
      if (GetBit(cnc_inp_keys_idx + current_check_circuit_idx, cnc_commit_perm_bits.GetArray())) {
        XOR_CodeWords(cnc_keys_share0[cnc_inp_keys_idx + current_check_circuit_idx], cnc_keys_share0[cnc_deltas_idx + current_check_circuit_idx]);
        XOR_CodeWords(cnc_keys_share1[cnc_inp_keys_idx + current_check_circuit_idx], cnc_keys_share1[cnc_deltas_idx + current_check_circuit_idx]);
      }

      //Compute the input keys
      XOR_128(cnc_keys[cnc_inp_keys_idx + current_check_circuit_idx], cnc_keys_share0[cnc_inp_keys_idx + current_check_circuit_idx], cnc_keys_share1[cnc_inp_keys_idx + current_check_circuit_idx]);

      //Add input permutation bits
      std::copy(commit_perm_bits_share0[inp_keys_idx + i],
                commit_perm_bits_share0[inp_keys_idx + (i + 1)],
                cnc_perm_bits_share0[cnc_inp_keys_idx + current_check_circuit_idx]);
      std::copy(commit_perm_bits_share1[inp_keys_idx + i],
                commit_perm_bits_share1[inp_keys_idx + (i + 1)],
                cnc_perm_bits_share1[cnc_inp_keys_idx + current_check_circuit_idx]);

      ++current_check_circuit_idx;
    } else if (current_eval_circuit_idx < exec_eval_circuits_to) {

      //Copy Delta
      std::copy(commit_keys_share0[deltas_idx + i], commit_keys_share0[deltas_idx + (i + 1)], aux_garbled_circuits_data[current_eval_circuit_idx].delta_commit0());
      std::copy(commit_keys_share1[deltas_idx + i], commit_keys_share1[deltas_idx + (i + 1)], aux_garbled_circuits_data[current_eval_circuit_idx].delta_commit1());

      //Copy inputs
      std::copy(commit_keys_share0[inp_keys_idx + i],
                commit_keys_share0[inp_keys_idx + (i + 1)],
                aux_garbled_circuits_data[current_eval_circuit_idx].inp_key_commit0());
      std::copy(commit_keys_share1[inp_keys_idx + i],
                commit_keys_share1[inp_keys_idx + (i + 1)],
                aux_garbled_circuits_data[current_eval_circuit_idx].inp_key_commit1());

      //Copy input permutation bits
      std::copy(commit_perm_bits_share0[inp_keys_idx + i],
                commit_perm_bits_share0[inp_keys_idx + (i + 1)],
                aux_garbled_circuits_data[current_eval_circuit_idx].inp_bit_commit0());
      std::copy(commit_perm_bits_share1[inp_keys_idx + i],
                commit_perm_bits_share1[inp_keys_idx + (i + 1)],
                aux_garbled_circuits_data[current_eval_circuit_idx].inp_bit_commit1());

      ++current_eval_circuit_idx;
    } else {
      completed_eval_copy = true;
    }
  }

  if (!completed_eval_copy) {
    std::cout << "Problem. Not enough eval circuits! Params should be set so this never occurs" << std::endl;
  }

//Send postulated perm bit values and prove correct using BatchDecommit
  exec_common_tools.chan.Send(cnc_commit_perm_bits.GetArray(), cnc_commit_perm_bits.size);
  bit_commit_snd.BatchDecommit(cnc_perm_bits_share0.GetArray(), cnc_perm_bits_share1.GetArray(), cnc_num_base_keys);

//BatchDecommit the cut-and-choose input and output keys. Needs to be done after BatchDecommit of perm bit values.
  exec_common_tools.chan.Send(cnc_keys.GetArray(), cnc_keys.size);
  commit_snd.BatchDecommit(cnc_keys_share0.GetArray(), cnc_keys_share1.GetArray(), cnc_num_commit_keys);
}

void DuploConstructor::InpBucketSendSolderings(std::vector<std::pair<std::string, uint32_t>>& input_components, CommonTools& exec_common_tools, Circuit& inp_bucket_circuit, uint32_t bucket_size, std::vector<uint32_t>& permuted_eval_ids_inv, uint32_t exec_components_from, uint32_t exec_components_to, std::vector<ConstGarbledCircuit>& aux_garbled_circuits_data) {

  uint32_t exec_num_components = exec_components_to - exec_components_from;
  uint32_t num_total_const_inputs = 0;
  std::vector<uint32_t> const_inp_pos;
  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = exec_components_from + i;
    std::string component_name = std::get<0>(input_components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];

    const_inp_pos.emplace_back(num_total_const_inputs);

    num_total_const_inputs += circuit.num_const_inp_wires;
  }

  uint32_t exec_prior_const_inp_wires = 0;
  for (int i = 0; i < exec_components_from; ++i) {
    std::string component_name = std::get<0>(input_components[i]);
    Circuit& circuit = string_to_circuit_map[component_name];
    exec_prior_const_inp_wires += circuit.num_const_inp_wires;
  }

  uint64_t constr_aux_size = ConstGarbledCircuit::AuxDataSize(inp_bucket_circuit);

  uint32_t num_solderings = num_total_const_inputs * bucket_size;
  BYTEArrayVector exec_permuted_aux_info(num_solderings, constr_aux_size);

  uint32_t solder_num_inp_keys, solder_num_out_keys, solder_num_deltas, solder_num_commit_keys, solder_num_base_keys, solder_inp_keys_idx, solder_out_keys_idx, solder_deltas_idx;
  ComputeIndices(num_solderings, inp_bucket_circuit, solder_num_inp_keys, solder_num_out_keys, solder_num_deltas, solder_num_commit_keys, solder_num_base_keys, solder_inp_keys_idx, solder_out_keys_idx, solder_deltas_idx);

  BYTEArrayVector solder_keys_share0(solder_num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector solder_keys_share1(solder_num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector solder_keys(solder_num_commit_keys, CSEC_BYTES);

  BYTEArrayVector solder_perm_bits_share0(solder_num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector solder_perm_bits_share1(solder_num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector solder_commit_perm_bits(BITS_TO_BYTES(solder_num_base_keys), 1);

  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = exec_components_from + i;
    std::string component_name = std::get<0>(input_components[curr_component]);
    uint32_t component_num = std::get<1>(input_components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];

    BYTEArrayVector component_aux_data;
    persistent_storage.ReadBuckets(component_name, AUXDATA, component_num, 1, component_aux_data);

    for (int j = 0; j < circuit.num_const_inp_wires; ++j) {
      for (int b = 0; b < bucket_size; ++b) {
        uint32_t curr_const_inp_wire = const_inp_pos[i] + j;
        uint32_t curr_inp_bucket_idx = curr_const_inp_wire * bucket_size + b;
        uint32_t global_inp_circuit_index = (exec_prior_const_inp_wires + curr_const_inp_wire) * bucket_size + b;
        std::copy(aux_garbled_circuits_data[permuted_eval_ids_inv[global_inp_circuit_index]].GetAuxArray(), aux_garbled_circuits_data[permuted_eval_ids_inv[global_inp_circuit_index]].GetAuxArray() + constr_aux_size, exec_permuted_aux_info[curr_inp_bucket_idx]);

        //Copy Delta soldering
        XOR_128(solder_keys[solder_deltas_idx + curr_inp_bucket_idx],
                ConstGarbledCircuit::delta_commit0(circuit, component_aux_data.GetArray()),
                ConstGarbledCircuit::delta_commit1(circuit, component_aux_data.GetArray()));
        XOR_128(solder_keys[solder_deltas_idx + curr_inp_bucket_idx], ConstGarbledCircuit::delta_commit0(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));
        XOR_128(solder_keys[solder_deltas_idx + curr_inp_bucket_idx],  ConstGarbledCircuit::delta_commit1(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));

        std::copy(ConstGarbledCircuit::delta_commit0(circuit, component_aux_data.GetArray()),
                  ConstGarbledCircuit::delta_commit0(circuit, component_aux_data.GetArray()) + CODEWORD_BYTES,
                  solder_keys_share0[solder_deltas_idx + curr_inp_bucket_idx]);
        XOR_CodeWords(solder_keys_share0[solder_deltas_idx + curr_inp_bucket_idx],
                      ConstGarbledCircuit::delta_commit0(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));

        std::copy(ConstGarbledCircuit::delta_commit1(circuit, component_aux_data.GetArray()),
                  ConstGarbledCircuit::delta_commit1(circuit, component_aux_data.GetArray()) + CODEWORD_BYTES,
                  solder_keys_share1[solder_deltas_idx + curr_inp_bucket_idx]);
        XOR_CodeWords(solder_keys_share1[solder_deltas_idx + curr_inp_bucket_idx],
                      ConstGarbledCircuit::delta_commit1(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));

        //Copy input soldering
        XOR_128(solder_keys[solder_inp_keys_idx + curr_inp_bucket_idx],
                ConstGarbledCircuit::inp_key_commit0(circuit, component_aux_data.GetArray(), j),
                ConstGarbledCircuit::inp_key_commit1(circuit, component_aux_data.GetArray(), j));

        XOR_128(solder_keys[solder_inp_keys_idx + curr_inp_bucket_idx], ConstGarbledCircuit::inp_key_commit0(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));
        XOR_128(solder_keys[solder_inp_keys_idx + curr_inp_bucket_idx],  ConstGarbledCircuit::inp_key_commit1(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));

        std::copy(ConstGarbledCircuit::inp_key_commit0(circuit, component_aux_data.GetArray(), j),
                  ConstGarbledCircuit::inp_key_commit0(circuit, component_aux_data.GetArray(), j + 1),
                  solder_keys_share0[solder_inp_keys_idx + curr_inp_bucket_idx]);
        XOR_CodeWords(solder_keys_share0[solder_inp_keys_idx + curr_inp_bucket_idx],
                      ConstGarbledCircuit::inp_key_commit0(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));

        std::copy(ConstGarbledCircuit::inp_key_commit1(circuit, component_aux_data.GetArray(), j),
                  ConstGarbledCircuit::inp_key_commit1(circuit, component_aux_data.GetArray(), j + 1),
                  solder_keys_share1[solder_inp_keys_idx + curr_inp_bucket_idx]);
        XOR_CodeWords(solder_keys_share1[solder_inp_keys_idx + curr_inp_bucket_idx],
                      ConstGarbledCircuit::inp_key_commit1(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));

        //Add input permutation bit soldering
        XORBit(
          solder_inp_keys_idx + curr_inp_bucket_idx,
          GetBit(0, ConstGarbledCircuit::inp_bit_commit0(circuit, component_aux_data.GetArray(), j)),
          GetBit(0, ConstGarbledCircuit::inp_bit_commit1(circuit, component_aux_data.GetArray(), j)),
          solder_commit_perm_bits.GetArray());

        XORBit(
          solder_inp_keys_idx + curr_inp_bucket_idx,
          GetBit(0, ConstGarbledCircuit::inp_bit_commit0(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx])),
          solder_commit_perm_bits.GetArray());
        XORBit(
          solder_inp_keys_idx + curr_inp_bucket_idx,
          GetBit(0, ConstGarbledCircuit::inp_bit_commit1(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx])),
          solder_commit_perm_bits.GetArray());

        //If xor of perm bits == 1 we XOR delta onto the soldering
        if (GetBit(solder_inp_keys_idx + curr_inp_bucket_idx, solder_commit_perm_bits.GetArray())) {

          XOR_128(solder_keys[solder_inp_keys_idx + curr_inp_bucket_idx], ConstGarbledCircuit::delta_commit0(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));
          XOR_128(solder_keys[solder_inp_keys_idx + curr_inp_bucket_idx],  ConstGarbledCircuit::delta_commit1(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));

          XOR_CodeWords(solder_keys_share0[solder_inp_keys_idx + curr_inp_bucket_idx], ConstGarbledCircuit::delta_commit0(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));
          XOR_CodeWords(solder_keys_share1[solder_inp_keys_idx + curr_inp_bucket_idx], ConstGarbledCircuit::delta_commit1(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));
        }

        //Add input permutation bit soldering decommit
        std::copy(ConstGarbledCircuit::inp_bit_commit0(circuit, component_aux_data.GetArray(), j),
                  ConstGarbledCircuit::inp_bit_commit0(circuit, component_aux_data.GetArray(), j + 1),
                  solder_perm_bits_share0[solder_inp_keys_idx + curr_inp_bucket_idx]);
        XOR_BitCodeWords(solder_perm_bits_share0[solder_inp_keys_idx + curr_inp_bucket_idx],
                         ConstGarbledCircuit::inp_bit_commit0(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));

        std::copy(ConstGarbledCircuit::inp_bit_commit1(circuit, component_aux_data.GetArray(), j),
                  ConstGarbledCircuit::inp_bit_commit1(circuit, component_aux_data.GetArray(), j + 1),
                  solder_perm_bits_share1[solder_inp_keys_idx + curr_inp_bucket_idx]);
        XOR_BitCodeWords(solder_perm_bits_share1[solder_inp_keys_idx + curr_inp_bucket_idx],
                         ConstGarbledCircuit::inp_bit_commit1(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));
      }
    }
  }

//Send postulated perm bit values and prove correct using BatchDecommit
  exec_common_tools.chan.Send(solder_commit_perm_bits.GetArray(), solder_commit_perm_bits.size);

  //Send postulated solderings and prove correct using BatchDecommit
  exec_common_tools.chan.Send(solder_keys.GetArray(), solder_keys.size);

  BitCommitSender bit_commit_snd(exec_common_tools, commit_seed_OTs0[CODEWORD_BITS], commit_seed_OTs1[CODEWORD_BITS]);
  bit_commit_snd.BatchDecommit(solder_perm_bits_share0.GetArray(), solder_perm_bits_share1.GetArray(), solder_num_base_keys);

  CommitSender commit_snd(exec_common_tools, commit_seed_OTs0.GetArray(), commit_seed_OTs1.GetArray());
  commit_snd.BatchDecommit(solder_keys_share0.GetArray(), solder_keys_share1.GetArray(), solder_num_commit_keys);

}