#include "duplo/duplo-evaluator.h"

DuploEvaluator::DuploEvaluator(CommonTools& common_tools, uint32_t num_max_parallel_execs) :
  Duplo(common_tools, num_max_parallel_execs),
  ot_rec(common_tools),
  commit_seed_OTs(NUM_COMMIT_SEED_OT, CSEC_BYTES),
  commit_seed_choices(BITS_TO_BYTES(NUM_COMMIT_SEED_OT), 1) {
}

void DuploEvaluator::Setup() {

  ot_rec.InitOTReceiver();

  //OTX for commitment seeds
  ot_rec.Receive(NUM_COMMIT_SEED_OT, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());

  for (int i = 0; i < NUM_COMMIT_SEED_OT; ++i) {
    common_tools.crypt.hash(commit_seed_OTs[i], CSEC_BYTES, commit_seed_OTs[i], CSEC_BYTES);
  }
}

void DuploEvaluator::PreprocessComponentType(std::string component_type, Circuit& circuit, uint32_t num_buckets, uint32_t num_parallel_execs, BucketType bucket_type) {

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

  PartitionBufferFixedNum(buckets_from, buckets_to, num_parallel_execs, num_buckets);
  PartitionBufferFixedNum(eval_circuits_from, eval_circuits_to, num_parallel_execs, num_eval_circuits);

  std::vector<EvalGarbledCircuit> aux_garbled_circuits_data(num_eval_circuits, EvalGarbledCircuit(circuit, 0));

  BYTEArrayVector eval_hash(num_eval_circuits, CSEC_BYTES);

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    uint64_t exec_prg_counter = curr_prg_counter;
    curr_prg_counter += FIXED_PRG_INC_NUMBER;

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

  auto component_commit_cnc_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(component_commit_cnc_begin, component_commit_cnc_end, num_buckets, "ComponentCommitCNC");
#endif

  uint64_t const_inp_perm_decommits_bytes = circuit.num_const_inp_wires * 2 * BIT_CODEWORD_BYTES * num_buckets;
  uint64_t tables_bytes = GarbledCircuit::TotalTableSize(circuit) * num_eval_circuits;
  uint64_t solderings_bytes = EvalGarbledCircuit::SolderingsSize(circuit) * num_eval_circuits;
  uint64_t auxdata_bytes = EvalGarbledCircuit::AuxDataSize(circuit) * num_buckets;

  persistent_storage.PrepareFile(component_type, TABLES, tables_bytes);
  persistent_storage.PrepareFile(component_type, SOLDERINGS, solderings_bytes);
  persistent_storage.PrepareFile(component_type, AUXDATA, auxdata_bytes);

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

  auto component_bucketing_begin = GET_TIME();

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {
    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &aux_garbled_circuits_data, &eval_hash, &buckets_from, &buckets_to, exec_id, &circuit, bucket_size, &permuted_eval_ids_inv, &component_type] (int id) {

      BucketAndReceiveEvalCircuits(component_type, exec_common_tools, circuit, bucket_size, permuted_eval_ids_inv, buckets_from[exec_id], buckets_to[exec_id], aux_garbled_circuits_data, eval_hash);
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

void DuploEvaluator::SolderGarbledComponents(std::string& res_component, ComposedCircuit& composed_circuit, uint32_t num_parallel_execs) {

  string_to_composed_circuit_map.emplace(res_component, composed_circuit);

  uint32_t num_inp_wire_components = composed_circuit.circuits.size() - composed_circuit.num_inp_circuits;

  std::vector<int> inp_wire_components_from, inp_wire_components_to;
  PartitionBufferFixedNum(inp_wire_components_from, inp_wire_components_to, num_parallel_execs, num_inp_wire_components);

  uint32_t num_total_solderings = 0;
  for (int l = 0; l < num_inp_wire_components; ++l) {
    uint32_t curr_component = composed_circuit.num_inp_circuits + l;

    std::string inp_wire_component_name(std::get<0>(composed_circuit.circuits[curr_component]));
    Circuit& circuit = string_to_circuit_map[inp_wire_component_name];

    num_total_solderings += (circuit.num_inp_wires + composed_circuit.out_wire_holders[curr_component].size());
  }

  persistent_storage.PrepareFile(res_component, VERTICAL_SOLDERINGS, num_total_solderings * CSEC_BYTES);

  std::vector<std::future<void>> futures;
  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();
    futures.emplace_back(thread_pool.push([this, &exec_common_tools, &res_component, &composed_circuit, &inp_wire_components_from, &inp_wire_components_to, exec_id] (int id) {

      ReceiveAndStoreSolderings(exec_common_tools, res_component, composed_circuit, inp_wire_components_from[exec_id], inp_wire_components_to[exec_id]);
    }));
  }

  for (std::future<void>& f : futures) {
    f.wait();
  }

}

void DuploEvaluator::EvalComposedComponents(std::string& res_component, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& eval_output_keys, uint32_t num_parallel_execs) {

  ComposedCircuit& composed_circuit = string_to_composed_circuit_map[res_component];

  //All input circuits
  std::vector<std::pair<std::string, uint32_t>> input_components;
  for (int c = 0; c < composed_circuit.num_inp_circuits; ++c) {
    input_components.emplace_back(composed_circuit.circuits[c]);
  }
  std::vector<BYTEArrayVector> input_components_outputs(composed_circuit.num_inp_circuits);

  //false meaning we do not send back the keys in input_components_outputs during this call. This is because we only send back the final output keys
  EvalComponents(input_components, inputs, input_components_outputs, num_parallel_execs, false);

  BYTEArrayVector output_keys(GetNumTotalOutWires(composed_circuit), CSEC_BYTES);

  uint32_t curr_out_pos = GetNumInpWires(composed_circuit);
  for (int l = 0; l < composed_circuit.num_inp_circuits; ++l) {

    std::copy(input_components_outputs[l].GetArray(), input_components_outputs[l].GetArray() + input_components_outputs[l].size, output_keys[curr_out_pos]);
    curr_out_pos += input_components_outputs[l].num_entries;
  }

  //All non-input circuits
  //skip input layer, so start at 1
  uint32_t current_layer_start_idx = composed_circuit.circuits_in_layer[0].size();
  for (int l = 1; l < composed_circuit.circuits_in_layer.size(); ++l) {
    uint32_t num_layer_circuits = composed_circuit.circuits_in_layer[l].size();
    std::vector<int> layer_circuit_from, layer_circuit_to;
    PartitionBufferFixedNum(layer_circuit_from, layer_circuit_to, num_parallel_execs, num_layer_circuits);

    std::vector<std::future<void>> futures;
    for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

      CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();
      futures.emplace_back(thread_pool.push([this, &exec_common_tools, &res_component, &output_keys, &layer_circuit_from, &layer_circuit_to, current_layer_start_idx, exec_id] (int id) {

        EvalComposedComponent(exec_common_tools, res_component, layer_circuit_from[exec_id], layer_circuit_to[exec_id], current_layer_start_idx, output_keys);
      }));

      current_layer_start_idx += composed_circuit.circuits_in_layer[l].size();
    }

    //Cannot continue to next layer, until this one finishes completely
    for (std::future<void>& f : futures) {
      f.wait();
    }
  }

  //Write final output wires to eval_output_keys and send constructor keys to constructor
  uint32_t num_circuits = composed_circuit.circuits.size();
  BYTEArrayVector const_output_keys(GetNumOutWires(composed_circuit, CONST_OUT), CSEC_BYTES);
  curr_out_pos = 0;
  for (int l = num_circuits - composed_circuit.num_out_circuits; l < num_circuits; ++l) { //run through output circuits
    std::string component_name(std::get<0>(composed_circuit.circuits[l]));
    Circuit& circuit = string_to_circuit_map[component_name];

    eval_output_keys.emplace_back(BYTEArrayVector(circuit.num_eval_out_wires, CSEC_BYTES));

    uint32_t component_out_start_pos = composed_circuit.out_wire_holder_to_wire_idx[l];
    uint32_t const_keys_out_start = component_out_start_pos + circuit.const_out_wires_start;
    uint32_t eval_keys_out_start = component_out_start_pos + circuit.eval_out_wires_start;
    
    std::copy(output_keys[const_keys_out_start], output_keys[const_keys_out_start + circuit.num_const_out_wires], const_output_keys[curr_out_pos]);
    curr_out_pos += circuit.num_const_out_wires;
    
    uint32_t curr_idx = l - (num_circuits - composed_circuit.num_out_circuits);
    std::copy(output_keys[eval_keys_out_start], output_keys[eval_keys_out_start + circuit.num_eval_out_wires], eval_output_keys[curr_idx].GetArray());
  }

  common_tools.chan.Send(const_output_keys.GetArray(), const_output_keys.size);
}

void DuploEvaluator::PrepareComponents(std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t num_parallel_execs) {

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
    std::cout << "Bad number auth of parallel execs used! Need to be multiple of total garbled components" << std::endl;
    // throw std::runtime_error("Bad number auth of parallel execs used! Need to be multiple of total garbled components");
  }

  uint64_t num_total_auth_buckets = num_circuit_auth_buckets + num_total_inputs;

  std::vector<std::future<void>> execs_finished(num_parallel_execs);

  //Compute parameters
  long double check_factor;
  uint32_t auth_size;
  bool negate_check_factor;

  auto t_param_start = GET_TIME();
  FindBestMajorityParams(num_total_auth_buckets, auth_size, check_factor, negate_check_factor, 2);
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

  uint64_t num_eval_auths = num_total_auth_buckets * auth_size;

  std::vector<int> eval_auths_from, eval_auths_to, input_components_from, input_components_to;
  PartitionBufferFixedNum(eval_auths_from, eval_auths_to, num_parallel_execs, num_eval_auths);
  PartitionBufferFixedNum(input_components_from, input_components_to, num_parallel_execs, input_components.size());

  BYTEArrayVector aux_auth_data(num_eval_auths, CODEWORD_BYTES);
  std::vector<BYTEArrayVector> eval_auths(num_eval_auths, BYTEArrayVector(2, CSEC_BYTES));
  std::vector<uint32_t> eval_auths_ids(num_eval_auths);
  uint8_t aux_auth_delta_data[CODEWORD_BYTES];

  std::mutex delta_updated_mutex;
  std::condition_variable delta_updated_cond_val;
  bool delta_updated = false;
  std::tuple<std::mutex&, std::condition_variable&, bool&> delta_signal = make_tuple(std::ref(delta_updated_mutex), std::ref(delta_updated_cond_val), std::ref(delta_updated));

  persistent_storage.PrepareFile(EVAL_PREPROCESS_PREFIX, INPUT_PERM_BITS, BITS_TO_BYTES(num_total_eval_inputs));

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    uint64_t exec_prg_counter = curr_prg_counter;
    curr_prg_counter += FIXED_PRG_INC_NUMBER;

    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();
    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &eval_auths, &aux_auth_data, &eval_auths_ids, &aux_auth_delta_data, &delta_signal, &eval_auths_from, &eval_auths_to, &input_components, &input_components_from, &input_components_to, exec_id, exec_prg_counter, check_factor, negate_check_factor] (int id) {

      uint32_t exec_num_auths = eval_auths_to[exec_id] - eval_auths_from[exec_id];

      float slack_val, repl_factor;
      ComputeCheckFraction(check_factor, exec_num_auths, slack_val, repl_factor, negate_check_factor);

      uint32_t exec_num_total_auths = ceil(repl_factor * exec_num_auths);

      CommitAuthAndCutAndChoose(exec_common_tools, exec_num_total_auths, exec_prg_counter, check_factor, negate_check_factor, eval_auths_from[exec_id], eval_auths_to[exec_id], eval_auths, aux_auth_data, eval_auths_ids, aux_auth_delta_data, delta_signal);

      if (!DecommitEvalInputPermBits(exec_common_tools, input_components, input_components_from[exec_id], input_components_to[exec_id])) {
        std::cout << "Abort, DecommitEvalInputPermBits failed!" << std::endl;
        throw std::runtime_error("Abort, DecommitEvalInputPermBits failed!");
      }


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

  uint64_t auth_input_bytes = 2 * CSEC_BYTES * num_total_inputs * auth_size;
  uint64_t auth_input_solderings_bytes = CSEC_BYTES * num_total_inputs * auth_size;
  uint64_t auth_input_delta_solderings_bytes = CSEC_BYTES * input_components.size();
  uint64_t auth_input_ids_bytes = sizeof(uint32_t) * num_total_inputs * auth_size;
  persistent_storage.PrepareFile(AUTHS_INPUT_PREFIX, AUTHS, auth_input_bytes);
  persistent_storage.PrepareFile(AUTHS_INPUT_PREFIX, AUTHS_SOLDERINGS, auth_input_solderings_bytes);
  persistent_storage.PrepareFile(AUTHS_INPUT_PREFIX, AUTHS_DELTA_SOLDERINGS, auth_input_delta_solderings_bytes);
  persistent_storage.PrepareFile(AUTHS_INPUT_PREFIX, AUTHS_IDS, auth_input_ids_bytes);

  auto prepare_eval_bucketing_begin = GET_TIME();
  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {
    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &exec_common_tools, &eval_auths, &aux_auth_data, &aux_auth_delta_data, &session_circuit_buckets_from, &session_circuit_buckets_to, exec_id, &permuted_eval_ids_inv, &eval_auths_ids, &input_components, &input_components_from, &input_components_to, &input_components_auth_start_pos, auth_size] (int id) {

      BucketAllAuths(exec_common_tools, auth_size, permuted_eval_ids_inv, session_circuit_buckets_from[exec_id], session_circuit_buckets_to[exec_id], eval_auths, aux_auth_data, eval_auths_ids, aux_auth_delta_data, input_components, input_components_from[exec_id], input_components_to[exec_id], input_components_auth_start_pos);
    });
  }

  for (std::future<void>& r : execs_finished) {
    r.wait();
  }

  auto prepare_eval_bucketing_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(prepare_eval_bucketing_begin, prepare_eval_bucketing_end, num_circuit_buckets, "PrepareEvalBucketing");
#endif

  //Construct input buckets (constructor input extraction) for all input circuits
  PrepareInputBuckets(input_components, num_parallel_execs);

  //OTX code cannot be run in parallel with a global delta
  PreprocessEvalInputOTs(input_components);
}

void DuploEvaluator::EvalComponents(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& eval_output_keys, uint32_t num_parallel_execs, bool send_output_keys) {

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

    futures.emplace_back(thread_pool.push([this, &exec_common_tools, &components, &components_from, &components_to, &inputs, &eval_output_keys, exec_inputs_used, num_parallel_execs, exec_id, send_output_keys] (int id) {

      uint32_t exec_num_components = components_to[exec_id] - components_from[exec_id];

      //Construct aux information
      std::vector<uint32_t> eval_inp_sizes, const_inp_sizes, eval_inp_pos, const_inp_pos;
      std::vector<BYTEArrayVector> input_keys;
      uint32_t num_total_eval_inputs = 0;
      uint32_t num_total_const_inputs = 0;
      uint32_t num_total_eval_out_wires = 0;
      uint32_t num_total_const_out_wires = 0;
      for (int i = components_from[exec_id]; i < components_to[exec_id]; ++i) {
        std::string component_name = std::get<0>(components[i]);
        Circuit& circuit = string_to_circuit_map[component_name];
        input_keys.emplace_back(BYTEArrayVector(circuit.num_inp_wires, CSEC_BYTES));
        eval_inp_pos.emplace_back(num_total_eval_inputs);
        const_inp_pos.emplace_back(num_total_const_inputs);

        num_total_eval_inputs += circuit.num_eval_inp_wires;
        num_total_const_inputs += circuit.num_const_inp_wires;
        num_total_eval_out_wires += circuit.num_eval_out_wires;
        num_total_const_out_wires += circuit.num_const_out_wires;

        eval_inp_sizes.emplace_back(circuit.num_eval_inp_wires);
        const_inp_sizes.emplace_back(circuit.num_const_inp_wires);
      }

      //Read all input mask data from disk
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
      BYTEArrayVector check_bits(BITS_TO_BYTES(num_total_eval_inputs), 1);
      std::vector<uint8_t*> e_vec(exec_num_components);
      std::vector<uint8_t*> check_bits_vec(exec_num_components);
      uint32_t inc_pos = 0;

      for (int i = 0; i < exec_num_components; ++i) {
        uint32_t curr_component = components_from[exec_id] + i;
        std::string component_name = std::get<0>(components[curr_component]);
        uint32_t component_num = std::get<1>(components[curr_component]);
        Circuit& circuit = string_to_circuit_map[component_name];

        e_vec[i] = e.GetArray() + inc_pos;
        check_bits_vec[i] = check_bits.GetArray() + inc_pos;
        inc_pos += BITS_TO_BYTES(eval_inp_sizes[i]);

        if (num_total_eval_inputs > 0) {

          //e = y
          std::copy(inputs[curr_component].begin(), inputs[curr_component].end(), e_vec[i]);

          //Read decomitted eval inp perm bits from disc
          BYTEArrayVector input_perm_bits;
          persistent_storage.ReadBuckets(EVAL_PREPROCESS_PREFIX, INPUT_PERM_BITS, curr_component, BITS_TO_BYTES(eval_inp_sizes[i]), input_perm_bits);

          //e = y \xor b \xor b
          XOR_UINT8_T(e_vec[i], input_perm_bits.GetArray(), BITS_TO_BYTES(eval_inp_sizes[i]));
          std::copy(e_vec[i], e_vec[i] + BITS_TO_BYTES(eval_inp_sizes[i]), check_bits_vec[i]);

          //e = y \xor b \xor c
          for (int j = 0; j < eval_inp_sizes[i]; ++j) {
            XORBit(j, GetBit(eval_inp_pos[i] + j, choice_bits.GetArray()), e_vec[i]);
          }
        }

        //Construct commit shares
        BYTEArrayVector component_aux_data;
        persistent_storage.ReadBuckets(component_name, AUXDATA, component_num, 1, component_aux_data);

        //Construct current component delta soldering share
        std::copy(EvalGarbledCircuit::delta_share(circuit, component_aux_data.GetArray()),
                  EvalGarbledCircuit::delta_share(circuit, component_aux_data.GetArray()) + CODEWORD_BYTES,
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

          //Ensure that sender did not flip the input key by comitting to r_0 \xor Delta_i. If the key isn't flipped, but he still didn't commit to r_0, the EvalBuckets will reject as they also check the key (if it is either 0 or 1).
          if (GetLSB(input_keys[i][const_inp_sizes[i] + j]) != GetBit(j, check_bits_vec[i])) {
            std::cout << "Abort, sender cheated earlier in input commit, trying to flip input!" << std::endl;
            throw std::runtime_error("Abort, sender cheated earlier in input commit, trying to flip input!");
          }
        }
      }

      std::vector<BYTEArrayVector> exec_all_output_keys;
      if (num_parallel_execs == 1) {
        EvalInputBucketsParallel(components, components_from[exec_id], components_to[exec_id], input_keys, exec_all_output_keys);
      } else {
        EvalInputBucketsSerial(components, components_from[exec_id], components_to[exec_id], input_keys, exec_all_output_keys);
      }


      BYTEArrayVector exec_const_output_keys(num_total_const_out_wires, CSEC_BYTES);
      uint32_t curr_const_pos = 0;
      for (int l = 0; l < exec_num_components; ++l) {
        uint32_t curr_component = components_from[exec_id] + l;
        std::string component_name = std::get<0>(components[curr_component]);
        Circuit& circuit = string_to_circuit_map[component_name];

        std::copy(exec_all_output_keys[l][circuit.const_out_wires_start], exec_all_output_keys[l][circuit.const_out_wires_stop], exec_const_output_keys[curr_const_pos]);

        eval_output_keys[curr_component] = BYTEArrayVector(circuit.num_eval_out_wires, CSEC_BYTES);
        std::copy(exec_all_output_keys[l][circuit.eval_out_wires_start], exec_all_output_keys[l][circuit.eval_out_wires_stop], eval_output_keys[curr_component].GetArray());

        curr_const_pos += circuit.num_const_out_wires;
      }
      if (send_output_keys) {
        exec_common_tools.chan.Send(exec_const_output_keys.GetArray(), exec_const_output_keys.size);
      }

      // int num_runs = 5;
      // auto serial_start = GET_TIME();
      // for (int i = 0; i < num_runs; ++i) {
      //   EvalInputBucketsParallel(components, components_from[exec_id], components_to[exec_id], input_keys, output_keys);
      // }
      // auto serial_end = GET_TIME();

      // uint64_t serial_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(serial_end - serial_start).count();
      // std::cout << "Serial per circuit: " << (double) serial_nano / num_runs / exec_num_components / 1000000 << std::endl;

      // auto parallel_start = GET_TIME();
      // for (int i = 0; i < num_runs; ++i) {
      //   EvalInputBucketsSerial(components, components_from[exec_id], components_to[exec_id], input_keys, output_keys);
      // }
      // auto parallel_end = GET_TIME();


      // uint64_t parallel_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(parallel_end - parallel_start).count();


      // std::cout << "Parallel per circuit: " << (double) parallel_nano / num_runs / exec_num_components / 1000000 << std::endl;

    }));
  }

  for (std::future<void>& future : futures) {
    future.wait();
  }
}

void DuploEvaluator::DecodeKeys(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<BYTEArrayVector>& output_keys, std::vector<std::vector<uint8_t>>& outputs, uint32_t num_parallel_execs) {

  std::vector<int> components_from, components_to;
  PartitionBufferFixedNum(components_from, components_to, num_parallel_execs, components.size());

  std::vector<std::future<void>> futures;
  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {

    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    futures.emplace_back(thread_pool.push([this, &exec_common_tools, &components, &components_from, &components_to, &output_keys, &outputs, exec_id] (int id) {

      uint32_t exec_num_components = components_to[exec_id] - components_from[exec_id];

      std::vector<BYTEArrayVector> output_decodings;
      if (!DecommitOutPermBits(exec_common_tools, components, components_from[exec_id], components_to[exec_id], output_decodings)) {
        std::cout << "Abort, DecommitOutPermBits failed!" << std::endl;
        throw std::runtime_error("Abort, DecommitOutPermBits failed!");
      }

      for (int i = 0; i < exec_num_components; ++i) {
        uint32_t curr_component = components_from[exec_id] + i;
        std::string component_name = std::get<0>(components[curr_component]);
        Circuit& circuit = string_to_circuit_map[component_name];

        outputs[curr_component] = std::vector<uint8_t>(BITS_TO_BYTES(circuit.num_eval_out_wires));

        DecodeGarbledOutput(output_keys[curr_component].GetArray(), output_decodings[i].GetArray(), outputs[curr_component].data(), circuit.num_eval_out_wires);
      }
    }));
  }

  for (std::future<void>& f : futures) {
    f.wait();
  }
}

void DuploEvaluator::CommitReceiveAndCutAndChoose(CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_num_total_garbled, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_circuits_from, uint32_t exec_eval_circuits_to, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data, BYTEArrayVector& eval_hash) {

  uint32_t num_inp_keys, num_out_keys, num_deltas, num_commit_keys, num_base_keys, input_keys_idx, output_keys_idx, deltas_idx;
  ComputeIndices(exec_num_total_garbled, circuit, num_inp_keys, num_out_keys, num_deltas, num_commit_keys, num_base_keys, input_keys_idx, output_keys_idx, deltas_idx);

  CommitReceiver commit_rec(exec_common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());
  BitCommitReceiver bit_commit_rec(exec_common_tools, commit_seed_OTs[CODEWORD_BITS], commit_seed_choices[CODEWORD_BYTES]);

  BYTEArrayVector commit_keys_share(num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector commit_perm_bits_share(num_base_keys, BIT_CODEWORD_BYTES);

  //Commit to keys
  if (!commit_rec.Commit(num_commit_keys, commit_keys_share, exec_prg_counter, deltas_idx)) {
    std::cout << "Abort, key commit failed!" << std::endl;;
    throw std::runtime_error("Abort, key commit failed!");
  }
  if (!bit_commit_rec.Commit(num_base_keys, commit_perm_bits_share, exec_prg_counter)) {
    std::cout << "Abort, perm_bit commit failed!" << std::endl;;
    throw std::runtime_error("Abort, perm_bit commit failed!");
  }

  BYTEArrayVector out_wire_commit_corrections(num_out_keys, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(out_wire_commit_corrections.GetArray(), out_wire_commit_corrections.size);

  BYTEArrayVector garb_circuit_hashes(exec_num_total_garbled, CSEC_BYTES);
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

  BYTEArrayVector cnc_perm_bits_share(cnc_num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector cnc_keys_share(cnc_num_commit_keys, CODEWORD_BYTES);

  //Receive postulated perm_bit values
  BYTEArrayVector cnc_commit_perm_bits(BITS_TO_BYTES(cnc_num_base_keys), 1);
  exec_common_tools.chan.ReceiveBlocking(cnc_commit_perm_bits.GetArray(), cnc_commit_perm_bits.size);

  uint32_t current_check_circuit_idx = 0;
  uint32_t current_eval_circuit_idx = exec_eval_circuits_from;
  for (int i = 0; i < exec_num_total_garbled; ++i) {
    if (GetBit(i, cnc_check_circuits.data())) { //Checked circuit

      //Add delta
      std::copy(commit_keys_share[deltas_idx + i], commit_keys_share[deltas_idx + (i + 1)], cnc_keys_share[cnc_deltas_idx + current_check_circuit_idx]);

      //Add inputs
      std::copy(commit_keys_share[input_keys_idx + i * circuit.num_inp_wires], commit_keys_share[input_keys_idx + (i + 1) * circuit.num_inp_wires], cnc_keys_share[cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires]);
      for (int j = 0; j < circuit.num_inp_wires; ++j) {
        if (GetBit(cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j, cnc_commit_perm_bits.GetArray())) {
          XOR_CodeWords(cnc_keys_share[cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j], cnc_keys_share[cnc_deltas_idx + current_check_circuit_idx]);
        }
      }

      //Add outputs
      std::copy(commit_keys_share[output_keys_idx + i * circuit.num_out_wires], commit_keys_share[output_keys_idx + (i + 1) * circuit.num_out_wires], cnc_keys_share[cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires]);
      for (int j = 0; j < circuit.num_out_wires; ++j) {
        if (GetBit(cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j, cnc_commit_perm_bits.GetArray())) {
          XOR_CodeWords(cnc_keys_share[cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j], cnc_keys_share[cnc_deltas_idx + current_check_circuit_idx]);
        }
      }

      //Add input permutation bits
      std::copy(commit_perm_bits_share[input_keys_idx + i * circuit.num_inp_wires], commit_perm_bits_share[input_keys_idx + (i + 1) * circuit.num_inp_wires], cnc_perm_bits_share[cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires]);

      //Add output permutation bits
      std::copy(commit_perm_bits_share[output_keys_idx + i * circuit.num_out_wires], commit_perm_bits_share[output_keys_idx + (i + 1) * circuit.num_out_wires], cnc_perm_bits_share[cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires]);

      ++current_check_circuit_idx;
    }
  }

  //Batch decommit these values
  if (!bit_commit_rec.BatchDecommit(cnc_perm_bits_share.GetArray(), cnc_num_base_keys, cnc_commit_perm_bits.GetArray())) {
    std::cout << "Abort, cut-and-choose bit decommit failed!" << std::endl;;
    throw std::runtime_error("Abort, cut-and-choose bit decommit failed!");
  }

  BYTEArrayVector cnc_keys(cnc_num_commit_keys, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(cnc_keys.GetArray(), cnc_keys.size);

  if (!commit_rec.BatchDecommit(cnc_keys_share.GetArray(), cnc_num_commit_keys, cnc_keys.GetArray())) {
    std::cout << "Abort, cut-and-choose decommit failed!" << std::endl;
    throw std::runtime_error("Abort, cut-and-choose decommit failed!");
  }


  GarblingHandler gh;
  std::vector<EvalGarbledCircuit> cnc_garbled_circuits(num_checked_circuits, EvalGarbledCircuit(circuit));

  BYTEArrayVector cnc_garb_circuit_hashes(num_checked_circuits, CSEC_BYTES);
  BYTEArrayVector output_keys(circuit.num_out_wires, CSEC_BYTES);
  BYTEArrayVector decommitted_output_keys(circuit.num_out_wires, CSEC_BYTES);

  current_check_circuit_idx = 0; //reset counter
  current_eval_circuit_idx = exec_eval_circuits_from; //reset counter
  bool completed_eval_copy = false;
  for (int i = 0; i < exec_num_total_garbled; ++i) {
    if (GetBit(i, cnc_check_circuits.data())) {

      //Check that lsb(Delta) == 1
      if (!GetLSB(cnc_keys[cnc_deltas_idx + current_check_circuit_idx])) {
        std::cout << "Abort, lsb(delta) was incorrect!" << std::endl;
        throw std::runtime_error("Abort, lsb(delta) was incorrect!");
      }

      //Check that lsb(base_inp_key)==0
      for (int j = 0; j < circuit.num_inp_wires; ++j) {
        if (GetLSB(cnc_keys[cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j]) ^
            GetBit(cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires + j, cnc_commit_perm_bits.GetArray())) {
          std::cout << "Abort, lsb(base_inp_key) != 0" << std::endl;
          throw std::runtime_error("Abort, lsb(base_inp_key) != 0");
        }
      }

      //Garble the circuit and store output keys to output_keys
      gh.GarbleCircuit(cnc_keys[cnc_input_keys_idx + current_check_circuit_idx * circuit.num_inp_wires], output_keys.GetArray(), cnc_keys[cnc_deltas_idx + current_check_circuit_idx], cnc_garbled_circuits[current_check_circuit_idx], cnc_garb_circuit_hashes[current_check_circuit_idx]);

      //Compute the decomitted output wires using out_wire_commit_corrections and the decomitted values in cnc_keys
      for (int j = 0; j < circuit.num_out_wires; ++j) {
        //Check that lsb(base_out_key)==0
        if (GetLSB(cnc_keys[cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j]) ^
            GetBit(cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j, cnc_commit_perm_bits.GetArray())) {
          std::cout << "Abort, lsb(base_out_key) != 0" << std::endl;
          throw std::runtime_error("Abort, lsb(base_out_key) != 0");
        }

        //Unmask the decomitted output keys
        XOR_128(decommitted_output_keys[j], out_wire_commit_corrections[i * circuit.num_out_wires + j], cnc_keys[cnc_output_keys_idx + current_check_circuit_idx * circuit.num_out_wires + j]);
      }

      //Check that the computed output keys match the decomitted ones
      if (!std::equal(output_keys.GetArray(), output_keys[circuit.num_out_wires - 1], decommitted_output_keys.GetArray())) {
        std::cout << "Abort, garbled circuit wrong output commits!" << std::endl;
        throw std::runtime_error("Abort, garbled circuit wrong output commits!");
      }

      // Finally check that the comitted tables match the cnc constructed tables by comparing the hash
      if (!std::equal(cnc_garb_circuit_hashes[current_check_circuit_idx], cnc_garb_circuit_hashes[current_check_circuit_idx] + CSEC_BYTES, garb_circuit_hashes[i])) {

        std::cout << "Abort, garbled tables wrongly constructed. Hash doesn't match!" << std::endl;
        throw std::runtime_error("Abort, garbled tables wrongly constructed. Hash doesn't match!");
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
      std::copy(commit_perm_bits_share[input_keys_idx + i * circuit.num_inp_wires], commit_perm_bits_share[input_keys_idx + (i + 1) * circuit.num_inp_wires], aux_garbled_circuits_data[current_eval_circuit_idx].inp_bit_share());

      //Copy output permutation bits
      std::copy(commit_perm_bits_share[output_keys_idx + i * circuit.num_out_wires], commit_perm_bits_share[output_keys_idx + (i + 1) * circuit.num_out_wires], aux_garbled_circuits_data[current_eval_circuit_idx].out_bit_share());

      //Add output correction
      std::copy(out_wire_commit_corrections[i * circuit.num_out_wires], out_wire_commit_corrections[(i + 1) * circuit.num_out_wires], aux_garbled_circuits_data[current_eval_circuit_idx].out_soldering());

      std::copy(garb_circuit_hashes[i], garb_circuit_hashes[i + 1], eval_hash[current_eval_circuit_idx]);

      ++current_eval_circuit_idx;
    } else {
      completed_eval_copy = true;
    }
  }

  if (!completed_eval_copy) {
    std::cout << "Problem. Not enough eval circuits! Params should be set so this never occurs" << std::endl;
  }
}

void DuploEvaluator::BucketAndReceiveEvalCircuits(std::string component_type, CommonTools & exec_common_tools, Circuit & circuit, uint32_t bucket_size, std::vector<uint32_t>& permuted_eval_ids_inv, uint32_t exec_buckets_from, uint32_t exec_buckets_to, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data, BYTEArrayVector & eval_hash) {

  uint64_t exec_num_buckets = exec_buckets_to - exec_buckets_from;
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

  uint8_t hash_value[CSEC_BYTES] = {0};
  for (int i = 0; i < exec_num_eval_circuits; ++i) {
    uint32_t global_circuit_index = exec_buckets_from * bucket_size + i;

    std::copy(aux_garbled_circuits_data[permuted_eval_ids_inv[global_circuit_index]].GetAuxArray(),
              aux_garbled_circuits_data[permuted_eval_ids_inv[global_circuit_index]].GetAuxArray() + total_eval_aux_size,
              exec_permuted_aux_info[i]);

    HashGarbledCircuitTables(circuit, exec_received_garbled_tables[i], hash_value);
    if (!std::equal(hash_value, hash_value + CSEC_BYTES, eval_hash[permuted_eval_ids_inv[global_circuit_index]])) {
      std::cout << "Abort, wrong eval garbled tables sent. Hash doesn't match!" << std::endl;
      throw std::runtime_error("Abort, wrong eval garbled tables sent. Hash doesn't match!");
    }
  }

  ////////////////////////////Soldering/////////////////////////////////////

  uint32_t num_soldering_circuits = (bucket_size - 1) * exec_num_eval_circuits;

  uint32_t solder_num_inp_keys, solder_num_out_keys, solder_num_deltas, solder_num_commit_keys, solder_num_base_keys, solder_input_keys_idx, solder_output_keys_idx, solder_deltas_idx;
  ComputeIndices(num_soldering_circuits, circuit, solder_num_inp_keys, solder_num_out_keys, solder_num_deltas, solder_num_commit_keys, solder_num_base_keys, solder_input_keys_idx, solder_output_keys_idx, solder_deltas_idx);

  BYTEArrayVector solder_keys_share(solder_num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector solder_perm_bits_share(solder_num_base_keys, BIT_CODEWORD_BYTES);

  //Receive the postulated solderings and check correctness using batch decommit
  BYTEArrayVector solder_keys(solder_num_commit_keys, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(solder_keys.GetArray(), solder_keys.size);

  BYTEArrayVector solder_commit_perm_bits(BITS_TO_BYTES(solder_num_base_keys), 1);
  //Receive postulated perm_bits values
  exec_common_tools.chan.ReceiveBlocking(solder_commit_perm_bits.GetArray(), solder_commit_perm_bits.size);

  int curr_head_circuit, curr_circuit, curr_solder_read_pos;
  for (int i = 0; i < exec_num_buckets; ++i) {
    curr_head_circuit = i * bucket_size;

    //Copy the head aux info for writing to disc
    std::copy(exec_permuted_aux_info[curr_head_circuit], exec_permuted_aux_info[curr_head_circuit] + eval_aux_size, exec_write_head_auxdata[i]); //Must be + eval_aux_size here!

    //Copy the head input soldering info for writing to disc
    std::copy(EvalGarbledCircuit::inp_soldering(circuit, exec_permuted_aux_info[curr_head_circuit]),
              EvalGarbledCircuit::inp_soldering(circuit, exec_permuted_aux_info[curr_head_circuit]) + solderings_size, exec_write_solderings[curr_head_circuit]);

    for (int l = 1; l < bucket_size; ++l) {
      curr_circuit = curr_head_circuit + l;
      curr_solder_read_pos = curr_circuit - (i + 1);

      //Add delta decommits
      std::copy(EvalGarbledCircuit::delta_share(circuit, exec_permuted_aux_info[curr_circuit]),
                EvalGarbledCircuit::delta_share(circuit, exec_permuted_aux_info[curr_circuit]) + CODEWORD_BYTES,
                solder_keys_share[solder_deltas_idx + curr_solder_read_pos]);
      XOR_CodeWords(solder_keys_share[solder_deltas_idx + curr_solder_read_pos], EvalGarbledCircuit::delta_share(circuit, exec_permuted_aux_info[curr_head_circuit]));

      //Copy curr delta soldering
      std::copy(solder_keys[solder_deltas_idx + curr_solder_read_pos],
                solder_keys[solder_deltas_idx + curr_solder_read_pos + 1],
                EvalGarbledCircuit::delta_soldering(circuit, exec_permuted_aux_info[curr_circuit]));

      for (int j = 0; j < circuit.num_inp_wires; ++j) {

        //Add input decommits
        std::copy(EvalGarbledCircuit::inp_key_share(circuit, exec_permuted_aux_info[curr_circuit], j),
                  EvalGarbledCircuit::inp_key_share(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_keys_share[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j]);
        XOR_CodeWords(solder_keys_share[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j], EvalGarbledCircuit::inp_key_share(circuit, exec_permuted_aux_info[curr_head_circuit], j));

        //Add input permutation bit soldering decommit
        std::copy(EvalGarbledCircuit::inp_bit_share(circuit, exec_permuted_aux_info[curr_circuit], j),
                  EvalGarbledCircuit::inp_bit_share(circuit, exec_permuted_aux_info[curr_circuit], j + 1),
                  solder_perm_bits_share[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j]);
        XOR_BitCodeWords(solder_perm_bits_share[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j], EvalGarbledCircuit::inp_bit_share(circuit, exec_permuted_aux_info[curr_head_circuit], j));

        //Add input decommits
        if (GetBit(solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j, solder_commit_perm_bits.GetArray())) {
          XOR_CodeWords(solder_keys_share[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j], EvalGarbledCircuit::delta_share(circuit, exec_permuted_aux_info[curr_circuit]));
        }

        //Add input solderings
        std::copy(solder_keys[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j],
                  solder_keys[solder_input_keys_idx + curr_solder_read_pos * circuit.num_inp_wires + j + 1],
                  EvalGarbledCircuit::inp_soldering(circuit, exec_permuted_aux_info[curr_circuit], j));
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
                  solder_perm_bits_share[solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j]);
        XOR_BitCodeWords(solder_perm_bits_share[solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j], EvalGarbledCircuit::out_bit_share(circuit, exec_permuted_aux_info[curr_head_circuit], j));

        if (GetBit(solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j, solder_commit_perm_bits.GetArray())) {
          XOR_CodeWords(solder_keys_share[solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j], EvalGarbledCircuit::delta_share(circuit, exec_permuted_aux_info[curr_circuit]));
        }

        //Copy output solderings
        XOR_128(EvalGarbledCircuit::out_soldering(circuit, exec_permuted_aux_info[curr_circuit], j),
                solder_keys[solder_output_keys_idx + curr_solder_read_pos * circuit.num_out_wires + j]);
      }

      //Copy curr soldering info for writing to disc
      std::copy(EvalGarbledCircuit::inp_soldering(circuit, exec_permuted_aux_info[curr_circuit]),
                EvalGarbledCircuit::inp_soldering(circuit, exec_permuted_aux_info[curr_circuit]) + solderings_size, exec_write_solderings[curr_circuit]);
    }
  }

  CommitReceiver commit_rec(exec_common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());
  if (!commit_rec.BatchDecommit(solder_keys_share.GetArray(), solder_num_commit_keys, solder_keys.GetArray())) {
    std::cout << "Abort, soldering decommit failed!" << std::endl;
    throw std::runtime_error("Abort, soldering decommit failed!");
  }

  BitCommitReceiver bit_commit_rec(exec_common_tools, commit_seed_OTs[CODEWORD_BITS], commit_seed_choices[CODEWORD_BYTES]);
  //Batch decommit these values
  if (!bit_commit_rec.BatchDecommit(solder_perm_bits_share.GetArray(), solder_num_base_keys, solder_commit_perm_bits.GetArray())) {
    std::cout << "Abort, soldering bit decommit failed!" << std::endl;;
    throw std::runtime_error("Abort, soldering bit decommit failed!");
  }

  //////////////////////////////Write to Disc/////////////////////////////////

  uint64_t exec_tables_write_pos = exec_buckets_from * bucket_size * garbled_table_size;
  uint64_t exec_solderings_write_pos = exec_buckets_from * bucket_size * solderings_size;
  uint64_t exec_auxdata_write_pos = exec_buckets_from * eval_aux_size;

  persistent_storage.WriteBuckets(component_type, TABLES, exec_buckets_from, exec_num_buckets, exec_received_garbled_tables.GetArray(), exec_tables_write_pos, exec_received_garbled_tables.size, bucket_size);

  persistent_storage.WriteBuckets(component_type, SOLDERINGS, exec_buckets_from, exec_num_buckets, exec_write_solderings.GetArray(), exec_solderings_write_pos, exec_write_solderings.size, bucket_size);

  persistent_storage.WriteBuckets(component_type, AUXDATA, exec_buckets_from, exec_num_buckets, exec_write_head_auxdata.GetArray(), exec_auxdata_write_pos, exec_write_head_auxdata.size, 1);
}

void DuploEvaluator::ReceiveAndStoreSolderings(CommonTools& exec_common_tools, std::string& res_component, ComposedCircuit& composed_circuit, uint32_t inp_wire_components_from, uint32_t inp_wire_components_to) {

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

  std::vector<uint32_t> global_inp_pos;
  uint32_t global_num_solderings_counter = 0;
  for (int l = composed_circuit.num_inp_circuits; l < composed_circuit.circuits.size(); ++l) {

    global_inp_pos.emplace_back(global_num_solderings_counter);
    std::string inp_wire_component_name(std::get<0>(composed_circuit.circuits[l]));
    Circuit& circuit = string_to_circuit_map[inp_wire_component_name];
    global_num_solderings_counter += (circuit.num_inp_wires + composed_circuit.out_wire_holders[l].size());
  }

  uint32_t exec_num_total_solderings = exec_num_total_wire_solderings + exec_num_total_deltas;

  BYTEArrayVector solder_keys_share(exec_num_total_solderings, CODEWORD_BYTES);
  BYTEArrayVector solder_perm_bits_share(exec_num_total_wire_solderings, BIT_CODEWORD_BYTES);

  //Receive the postulated solderings and check correctness using batch decommit
  BYTEArrayVector solder_keys(exec_num_total_solderings, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(solder_keys.GetArray(), solder_keys.size);

  //Receive postulated perm_bits values
  BYTEArrayVector solder_commit_perm_bits(BITS_TO_BYTES(exec_num_total_wire_solderings), 1);
  exec_common_tools.chan.ReceiveBlocking(solder_commit_perm_bits.GetArray(), solder_commit_perm_bits.size);

  for (int l = 0; l < exec_num_inp_wire_components; ++l) {
    uint32_t curr_component = composed_circuit.num_inp_circuits + inp_wire_components_from + l;

    std::string inp_wire_component_name(std::get<0>(composed_circuit.circuits[curr_component]));
    uint32_t inp_wire_component_num(std::get<1>(composed_circuit.circuits[curr_component]));
    Circuit& inp_circuit = string_to_circuit_map[inp_wire_component_name];

    BYTEArrayVector inp_wire_component_aux_info;
    persistent_storage.ReadBuckets(inp_wire_component_name, AUXDATA, inp_wire_component_num, 1, inp_wire_component_aux_info);

    //Add all input component values to soldering
    for (int j = 0; j < inp_circuit.num_inp_wires; ++j) {
      std::copy(EvalGarbledCircuit::inp_key_share(inp_circuit, inp_wire_component_aux_info.GetArray(), j),
                EvalGarbledCircuit::inp_key_share(inp_circuit, inp_wire_component_aux_info.GetArray(), j + 1),
                solder_keys_share[inp_pos[l] + j]);

      std::copy(EvalGarbledCircuit::inp_bit_share(inp_circuit, inp_wire_component_aux_info.GetArray(), j),
                EvalGarbledCircuit::inp_bit_share(inp_circuit, inp_wire_component_aux_info.GetArray(), j + 1),
                solder_perm_bits_share[perm_bit_inp_pos[l] + j]);
    }

    uint32_t curr_inp_wire = 0;
    for (int i = 0; i < composed_circuit.out_wire_holders[curr_component].size(); ++i) {

      //Add delta solderings from input wire component to all delta positions
      std::copy(EvalGarbledCircuit::delta_share(inp_circuit, inp_wire_component_aux_info.GetArray()),
                EvalGarbledCircuit::delta_share(inp_circuit, inp_wire_component_aux_info.GetArray()) + CODEWORD_BYTES,
                solder_keys_share[inp_pos[l] + inp_circuit.num_inp_wires + i]);

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
      XOR_CodeWords(solder_keys_share[inp_pos[l] + inp_circuit.num_inp_wires + i], EvalGarbledCircuit::delta_share(out_circuit, out_wire_component_aux_info.GetArray()));

      //Run through the soldering pairs and apply the soldering
      std::vector<uint32_t>& out_wires = std::get<1>(out_wire_component_pair);

      for (int j = 0; j < out_wires.size(); ++j) {
        XOR_CodeWords(solder_keys_share[inp_pos[l] + curr_inp_wire], EvalGarbledCircuit::out_key_share(out_circuit, out_wire_component_aux_info.GetArray(), out_wires[j]));

        //Add output perm bit decommits
        XOR_BitCodeWords(solder_perm_bits_share[perm_bit_inp_pos[l] + curr_inp_wire], EvalGarbledCircuit::out_bit_share(out_circuit, out_wire_component_aux_info.GetArray(), out_wires[j]));

        if (GetBit(perm_bit_inp_pos[l] + curr_inp_wire, solder_commit_perm_bits.GetArray())) {

          XOR_CodeWords(solder_keys_share[inp_pos[l] + curr_inp_wire], EvalGarbledCircuit::delta_share(inp_circuit, inp_wire_component_aux_info.GetArray()));
        }
        ++curr_inp_wire;
      }
    }

    uint32_t curr_soldering_inp_wire_component_idx = curr_component - composed_circuit.num_inp_circuits;

    persistent_storage.WriteBuckets(res_component, VERTICAL_SOLDERINGS, curr_soldering_inp_wire_component_idx, 1, solder_keys[inp_pos[l]], global_inp_pos[curr_soldering_inp_wire_component_idx] * CSEC_BYTES, (inp_circuit.num_inp_wires + composed_circuit.out_wire_holders[curr_component].size()) * CSEC_BYTES, 1);
  }

  CommitReceiver commit_rec(exec_common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());
  if (!commit_rec.BatchDecommit(solder_keys_share.GetArray(), exec_num_total_solderings, solder_keys.GetArray())) {
    std::cout << "Abort, vertical soldering decommit failed!" << std::endl;
    throw std::runtime_error("Abort, vertical soldering decommit failed!");
  }

  BitCommitReceiver bit_commit_rec(exec_common_tools, commit_seed_OTs[CODEWORD_BITS], commit_seed_choices[CODEWORD_BYTES]);
  if (!bit_commit_rec.BatchDecommit(solder_perm_bits_share.GetArray(), exec_num_total_wire_solderings, solder_commit_perm_bits.GetArray())) {
    std::cout << "Abort, vertical soldering bit decommit failed!" << std::endl;;
    throw std::runtime_error("Abort, vertical soldering bit decommit failed!");
  }
}

void DuploEvaluator::CommitAuthAndCutAndChoose(CommonTools & exec_common_tools, uint32_t exec_num_auths, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_auths_from, uint32_t exec_eval_auths_to, std::vector<BYTEArrayVector>& eval_auths, BYTEArrayVector & aux_auth_data, std::vector<uint32_t>& eval_auths_ids, uint8_t aux_auth_delta_data[], std::tuple<std::mutex&, std::condition_variable&, bool&>& delta_signal) {

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

  for (int i = 0; i < exec_num_auths; ++i) {
    if (GetBit(i, cnc_check_auths.data())) { //Checked auths

      //Add key shares
      std::copy(commit_keys_share[i], commit_keys_share[(i + 1)], cnc_keys_share[current_check_auth_idx]);

      if (GetBit(current_check_auth_idx, cnc_check_inputs.data())) {
        XOR_CodeWords(cnc_keys_share[current_check_auth_idx], aux_auth_delta_data);
      }

      ++current_check_auth_idx;
    }
  }

  BYTEArrayVector cnc_keys(cnc_num_auths, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(cnc_keys.GetArray(), cnc_keys.size);

  if (!commit_rec.BatchDecommit(cnc_keys_share.GetArray(), cnc_num_auths, cnc_keys.GetArray())) {
    std::cout << "Abort, auth cut-and-choose decommit failed!" << std::endl;
    throw std::runtime_error("Abort, auth cut-and-choose decommit failed!");
  }

  GarblingHandler gh;
  current_check_auth_idx = 0;
  uint32_t global_auth_idx;
  bool success = true;
  bool completed_eval_copy = false;
  for (int i = 0; i < exec_num_auths; ++i) {
    if (GetBit(i, cnc_check_auths.data())) { //Checked auths
      global_auth_idx = exec_eval_auths_from + i;
      if (!VerifyAuth(cnc_keys[current_check_auth_idx], auths[H_0_idx + i], auths[H_1_idx + i], global_auth_idx, gh.key_schedule)) {
        success = false;
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

  if (!success) {
    std::cout << "Abort, auth cut-and-choose eval failed!" << std::endl;
    throw std::runtime_error("Abort, auth cut-and-choose eval failed!");
  }

  if (!completed_eval_copy) {
    std::cout << "Problem. Not enough eval auths! Params should be set so this never occurs" << std::endl;
  }
}

void DuploEvaluator::BucketAllAuths(CommonTools & exec_common_tools, uint32_t auth_size, std::vector<uint32_t>& permuted_eval_ids_inv, std::vector<int>& session_circuit_buckets_from, std::vector<int>& session_circuit_buckets_to, std::vector<BYTEArrayVector>& eval_auths, BYTEArrayVector & aux_auth_data, std::vector<uint32_t>& eval_auths_ids, uint8_t aux_auth_delta_data[], std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t input_components_from, uint32_t input_components_to, std::vector<uint32_t>& input_components_auth_start_pos) {

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
  uint32_t exec_num_input_buckets = 0;
  for (int l = 0; l < exec_num_input_components; ++l) {
    uint32_t curr_component = input_components_from + l;
    std::string input_component_name = std::get<0>(input_components[curr_component]);
    Circuit& input_component = string_to_circuit_map[input_component_name];

    total_num_solderings += (auth_size * input_component.num_inp_wires + 1);
    exec_num_input_buckets += input_component.num_inp_wires;
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
                EvalGarbledCircuit::delta_share(session_circuit, curr_session_aux_info[i]) + CODEWORD_BYTES,
                solder_keys_share[curr_solder_write_pos]);
      XOR_CodeWords(solder_keys_share[curr_solder_write_pos], aux_auth_delta_data);

      ++curr_solder_write_pos;

      //Copy all bucket_size*session_circuit.num_out_wires solderings
      for (int j = 0; j < session_circuit.num_out_wires; ++j) {
        for (int a = 0; a < auth_size; ++a) {
          uint32_t perm_auth_idx = permuted_eval_ids_inv[(curr_session_bucket_idx * session_circuit.num_out_wires + j) * auth_size + a];

          std::copy(EvalGarbledCircuit::out_key_share(session_circuit, curr_session_aux_info[i], j),
                    EvalGarbledCircuit::out_key_share(session_circuit, curr_session_aux_info[i], j + 1),
                    solder_keys_share[curr_solder_write_pos]);

          XOR_CodeWords(solder_keys_share[curr_solder_write_pos], aux_auth_data[perm_auth_idx]);

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
    std::copy(EvalGarbledCircuit::delta_share(input_component, curr_circuit_aux_info.GetArray()),
              EvalGarbledCircuit::delta_share(input_component, curr_circuit_aux_info.GetArray()) + CODEWORD_BYTES,
              solder_keys_share[curr_solder_write_pos]);
    XOR_CodeWords(solder_keys_share[curr_solder_write_pos], aux_auth_delta_data);

    ++curr_solder_write_pos;

    for (int j = 0; j < input_component.num_inp_wires; ++j) {
      for (int a = 0; a < auth_size; ++a) {
        uint32_t perm_auth_idx = permuted_eval_ids_inv[input_components_auth_start_pos[curr_component] + j * auth_size + a];

        std::copy(EvalGarbledCircuit::inp_key_share(input_component, curr_circuit_aux_info.GetArray(), j),
                  EvalGarbledCircuit::inp_key_share(input_component, curr_circuit_aux_info.GetArray(), j + 1),
                  solder_keys_share[curr_solder_write_pos]);
        XOR_CodeWords(solder_keys_share[curr_solder_write_pos], aux_auth_data[perm_auth_idx]);

        ++curr_solder_write_pos;
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

          uint32_t perm_auth_idx = permuted_eval_ids_inv[(curr_session_bucket_idx * session_circuit.num_out_wires + j) * auth_size + a];

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

    uint64_t exec_auths_write_pos = session_circuit_buckets_from[l] * session_circuit.num_out_wires * auth_size * 2 * CSEC_BYTES;
    uint64_t exec_auths_solderings_write_pos = session_circuit_buckets_from[l] * session_circuit.num_out_wires * auth_size * CSEC_BYTES;
    uint64_t exec_auths_deltas_write_pos = session_circuit_buckets_from[l] * CSEC_BYTES;
    uint64_t exec_auths_ids_write_pos = session_circuit_buckets_from[l] * session_circuit.num_out_wires * auth_size * sizeof(uint32_t);

    //Write auths
    persistent_storage.WriteBuckets(session_component_type, AUTHS, exec_session_auth_bucket_from, exec_session_num_auth_buckets, exec_session_auths.GetArray(), exec_auths_write_pos, exec_session_auths.size, auth_size);

    //Write auth solderings
    persistent_storage.WriteBuckets(session_component_type, AUTHS_SOLDERINGS, exec_session_auth_bucket_from, exec_session_num_auth_buckets, exec_session_auths_solderings.GetArray(), exec_auths_solderings_write_pos, exec_session_auths_solderings.size, auth_size);

    //Write delta solderings
    persistent_storage.WriteBuckets(session_component_type, AUTHS_DELTA_SOLDERINGS, session_circuit_buckets_from[l], exec_session_num_circuit_buckets, exec_session_delta_solder.GetArray(), exec_auths_deltas_write_pos, exec_session_delta_solder.size, 1);

    //Write global auth ids
    persistent_storage.WriteBuckets(session_component_type, AUTHS_IDS, exec_session_auth_bucket_from, exec_session_num_auth_buckets, exec_session_global_ids.GetArray(), exec_auths_ids_write_pos, exec_session_global_ids.size, auth_size);
  }

  //Input authenticators
  if (exec_num_input_buckets > 0) {

    BYTEArrayVector exec_auths_input(exec_num_input_buckets * auth_size, 2 * CSEC_BYTES);
    BYTEArrayVector exec_auths_input_solderings(exec_num_input_buckets * auth_size, CSEC_BYTES);
    BYTEArrayVector exec_auths_input_delta_solder(exec_num_input_components, CSEC_BYTES);
    BYTEArrayVector exec_auths_input_global_ids(exec_num_input_buckets * auth_size, sizeof(uint32_t));

    uint32_t curr_inp_auth_start = 0;
    for (int l = 0; l < exec_num_input_components; ++l) {
      uint32_t curr_component = input_components_from + l;
      std::string input_component_name = std::get<0>(input_components[curr_component]);
      uint32_t input_component_num = std::get<1>(input_components[curr_component]);
      Circuit& input_component = string_to_circuit_map[input_component_name];

      std::copy(solder_keys[curr_solder_read_pos], solder_keys[curr_solder_read_pos + 1], exec_auths_input_delta_solder[l]);

      ++curr_solder_read_pos;

      //Copy all bucket_size*session_circuit.num_out_wires solderings
      for (int j = 0; j < input_component.num_inp_wires; ++j) {
        for (int a = 0; a < auth_size; ++a) {
          uint32_t perm_auth_idx = permuted_eval_ids_inv[input_components_auth_start_pos[curr_component] + j * auth_size + a];

          //Copy auths
          std::copy(
            eval_auths[perm_auth_idx][0],
            eval_auths[perm_auth_idx][0] + CSEC_BYTES,
            exec_auths_input[(curr_inp_auth_start + j) * auth_size + a]);

          std::copy(
            eval_auths[perm_auth_idx][1],
            eval_auths[perm_auth_idx][1] + CSEC_BYTES,
            exec_auths_input[(curr_inp_auth_start + j) * auth_size + a] + CSEC_BYTES);

          //Copy auth solderings
          std::copy(solder_keys[curr_solder_read_pos],
                    solder_keys[curr_solder_read_pos + 1],
                    exec_auths_input_solderings[(curr_inp_auth_start + j) * auth_size + a]);

          //Copy global idx
          std::copy((uint8_t*) & (eval_auths_ids[perm_auth_idx]),
                    (uint8_t*) & (eval_auths_ids[perm_auth_idx]) + sizeof(uint32_t),
                    exec_auths_input_global_ids[(curr_inp_auth_start + j) * auth_size + a]);

          ++curr_solder_read_pos;
        }
      }
      curr_inp_auth_start += input_component.num_inp_wires;
    }

    uint32_t exec_num_input_buckets_start = 0;
    for (int l = 0; l < input_components_from; ++l) {
      std::string input_component_name = std::get<0>(input_components[l]);
      Circuit& input_component = string_to_circuit_map[input_component_name];
      exec_num_input_buckets_start += input_component.num_inp_wires;
    }

    uint64_t exec_auths_input_write_pos = exec_num_input_buckets_start * auth_size * 2 * CSEC_BYTES;
    uint64_t exec_auths_input_solderings_write_pos = exec_num_input_buckets_start * auth_size * CSEC_BYTES;
    uint64_t exec_auths_input_deltas_write_pos = input_components_from * CSEC_BYTES;
    uint64_t exec_auths_input_ids_write_pos = exec_num_input_buckets_start * auth_size * sizeof(uint32_t);

    //Write auths
    persistent_storage.WriteBuckets(AUTHS_INPUT_PREFIX, AUTHS, exec_num_input_buckets_start, exec_num_input_buckets, exec_auths_input.GetArray(), exec_auths_input_write_pos, exec_auths_input.size, auth_size);

    //Write auth solderings
    persistent_storage.WriteBuckets(AUTHS_INPUT_PREFIX, AUTHS_SOLDERINGS, exec_num_input_buckets_start, exec_num_input_buckets, exec_auths_input_solderings.GetArray(), exec_auths_input_solderings_write_pos, exec_auths_input_solderings.size, auth_size);

    //Write delta solderings
    persistent_storage.WriteBuckets(AUTHS_INPUT_PREFIX, AUTHS_DELTA_SOLDERINGS, input_components_from, exec_num_input_components, exec_auths_input_delta_solder.GetArray(), exec_auths_input_deltas_write_pos, exec_auths_input_delta_solder.size, 1);

    //Write global auth ids
    persistent_storage.WriteBuckets(AUTHS_INPUT_PREFIX, AUTHS_IDS, exec_num_input_buckets_start, exec_num_input_buckets, exec_auths_input_global_ids.GetArray(), exec_auths_input_ids_write_pos, exec_auths_input_global_ids.size, auth_size);
  }
}

void DuploEvaluator::PrepareInputBuckets(std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t num_parallel_execs) {
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


  std::vector<EvalGarbledCircuit> aux_garbled_circuits_data(num_eval_circuits, EvalGarbledCircuit(inp_bucket_circuit, 0));

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
  // circuit_info.emplace_back(std::make_tuple(EVAL_INP_BUCKET_PREFIX, inp_bucket_circuit, num_buckets));

  auto inp_bucket_commit_cnc_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(inp_bucket_commit_cnc_begin, inp_bucket_commit_cnc_end, input_components.size(), "InpBucketCommitCNC");
#endif

  uint64_t const_inp_perm_decommits_bytes = inp_bucket_circuit.num_const_inp_wires * 2 * BIT_CODEWORD_BYTES * num_buckets;
  uint64_t tables_bytes = GarbledCircuit::TotalTableSize(inp_bucket_circuit) * num_eval_circuits;
  uint64_t solderings_bytes = EvalGarbledCircuit::SolderingsSize(inp_bucket_circuit) * num_eval_circuits;
  uint64_t auxdata_bytes = EvalGarbledCircuit::AuxDataSize(inp_bucket_circuit) * num_buckets;

  persistent_storage.PrepareFile(EVAL_INP_BUCKET_PREFIX, SOLDERINGS, solderings_bytes);
  // persistent_storage.PrepareFile(EVAL_INP_BUCKET_PREFIX, AUXDATA, auxdata_bytes);

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

  auto inp_bucketing_begin = GET_TIME();

  for (int exec_id = 0; exec_id < num_parallel_execs; ++exec_id) {
    CommonTools& exec_common_tools = *common_tools_vec[exec_id].get();

    //Starts the current execution
    execs_finished[exec_id] = thread_pool.push([this, &input_components, &exec_common_tools, &aux_garbled_circuits_data, &inp_buckets_from, &inp_buckets_to, exec_id, bucket_size, &permuted_eval_ids_inv] (int id) {

      InpBucketReceiveSolderings(input_components, exec_common_tools, inp_bucket_circuit, bucket_size, permuted_eval_ids_inv, inp_buckets_from[exec_id], inp_buckets_to[exec_id], aux_garbled_circuits_data);
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

void DuploEvaluator::PreprocessEvalInputOTs(std::vector<std::pair<std::string, uint32_t>>& input_components) {

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

  auto otx_start = GET_TIME();
  ot_rec.Receive(num_ots, input_masks.GetArray(), input_masks_choices.GetArray());
  auto otx_end = GET_TIME();

  //Run Random Commit
  uint32_t num_commits = num_ots + 1;
  BYTEArrayVector commit_keys_share(num_commits, CODEWORD_BYTES);

  CommitReceiver commit_rec(common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());
  uint64_t exec_prg_counter = curr_prg_counter;
  curr_prg_counter += FIXED_PRG_INC_NUMBER;
  commit_rec.Commit(num_commits, commit_keys_share, exec_prg_counter);

  //Run chosen commit
  BYTEArrayVector input_mask_corrections(num_commits, CSEC_BYTES);
  common_tools.chan.ReceiveBlocking(input_mask_corrections.GetArray(), input_mask_corrections.size);

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
  common_tools.chan.Send(cnc_ot_values.data(),  SSEC * CSEC_BYTES + SSEC_BYTES);

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
  common_tools.chan.ReceiveBlocking(chosen_decommit_shares0.GetArray(), chosen_decommit_shares0.size);
  common_tools.chan.ReceiveBlocking(chosen_decommit_shares1.GetArray(), chosen_decommit_shares1.size);

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

  auto preprocess_inputs_end = GET_TIME();

#ifdef DUPLO_PRINT
  PrintTimePerBucket(otx_start, otx_end, num_components, "Delta-OTX per OT");
  PrintTimePerBucket(preprocess_inputs_begin, preprocess_inputs_end, num_components, "PreprocessEvalInputOTs");
#endif
}

bool DuploEvaluator::DecommitEvalInputPermBits(CommonTools& exec_common_tools, std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t components_from, uint32_t components_to) {

  uint32_t exec_num_components = components_to - components_from;

  //Read inp perm bits corresponding to components
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
    return true;
  }

  BYTEArrayVector b_share(num_total_eval_inputs, BIT_CODEWORD_BYTES);

  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = components_from + i;
    std::string component_name = std::get<0>(input_components[curr_component]);
    uint32_t component_num = std::get<1>(input_components[curr_component]);
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
  exec_common_tools.chan.ReceiveBlocking(b.GetArray(), b.size);

  BitCommitReceiver bit_commit_rec(exec_common_tools, commit_seed_OTs[CODEWORD_BITS], commit_seed_choices[CODEWORD_BYTES]);
  if (!bit_commit_rec.BatchDecommit(b_share.GetArray(), num_total_eval_inputs, b.GetArray())) {
    return false;
  }

  std::vector<uint8_t*> b_vec(exec_num_components);
  uint32_t inc_pos = 0;
  for (int i = 0; i < exec_num_components; ++i) {
    b_vec[i] = b.GetArray() + inc_pos;
    inc_pos += BITS_TO_BYTES(eval_inp_sizes[i]);
  }

  uint32_t exec_prior_eval_inp_wires = 0;
  for (int i = 0; i < components_from; ++i) {
    std::string component_name = std::get<0>(input_components[i]);
    Circuit& circuit = string_to_circuit_map[component_name];
    exec_prior_eval_inp_wires += circuit.num_eval_inp_wires;
  }
  uint32_t exec_start_write_pos = BITS_TO_BYTES(exec_prior_eval_inp_wires);

  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = components_from + i;
    persistent_storage.WriteBuckets(EVAL_PREPROCESS_PREFIX, INPUT_PERM_BITS, curr_component, 1, b_vec[i], exec_start_write_pos + BITS_TO_BYTES(eval_inp_pos[i]), BITS_TO_BYTES(eval_inp_sizes[i]), 1);
  }

  return true;
}

void DuploEvaluator::EvalComposedComponent(CommonTools& exec_common_tools, std::string& res_component, uint32_t components_from, uint32_t components_to, uint32_t current_layer_start_idx, BYTEArrayVector& output_keys) {

  ComposedCircuit& composed_circuit = string_to_composed_circuit_map[res_component];

  uint32_t num_circuits = components_to - components_from;
  for (int l = 0; l < num_circuits; ++l) {
    uint32_t curr_circuit_idx = current_layer_start_idx + components_from + l;
    std::string component_name = std::get<0>(composed_circuit.circuits[curr_circuit_idx]);
    uint32_t component_num = std::get<1>(composed_circuit.circuits[curr_circuit_idx]);
    Circuit& circuit = string_to_circuit_map[component_name];

    uint32_t curr_soldering_inp_wire_component_idx = curr_circuit_idx - composed_circuit.num_inp_circuits;

    BYTEArrayVector curr_inp_keys(circuit.num_inp_wires, CSEC_BYTES);
    BYTEArrayVector read_solderings;
    persistent_storage.ReadBuckets(res_component, VERTICAL_SOLDERINGS, curr_soldering_inp_wire_component_idx, 1, read_solderings);

    uint32_t curr_inp_wire = 0;
    for (int i = 0; i < composed_circuit.out_wire_holders[curr_circuit_idx].size(); ++i) {

      std::pair<uint32_t, std::vector<uint32_t>>& curr_out_wire_holder_pair = composed_circuit.out_wire_holders[curr_circuit_idx][i];
      uint32_t circuit_idx = std::get<0>(curr_out_wire_holder_pair);
      std::pair<std::string, uint32_t>& curr_out_wire_holder = composed_circuit.circuits[circuit_idx];
      std::vector<uint32_t> out_wires = std::get<1>(curr_out_wire_holder_pair);

      uint32_t out_start_pos = composed_circuit.out_wire_holder_to_wire_idx[circuit_idx];

      for (int j = 0; j < out_wires.size(); ++j) {
        std::copy(output_keys[out_start_pos + out_wires[j]], output_keys[out_start_pos + out_wires[j] + 1], curr_inp_keys[curr_inp_wire]);

        if (GetLSB(curr_inp_keys[curr_inp_wire])) {
          XOR_128(curr_inp_keys[curr_inp_wire], read_solderings.GetArray() + (circuit.num_inp_wires + i) * CSEC_BYTES);
        }
        ++curr_inp_wire;
      }
    }

    //XOR onto current non-head circuit the input solderings of head circuit. Effectively applying vertical solderings
    XOR_UINT8_T(curr_inp_keys.GetArray(), read_solderings.GetArray(), circuit.num_inp_wires * CSEC_BYTES);

    //Where to write out_keys for this component
    uint32_t component_out_start_pos = composed_circuit.out_wire_holder_to_wire_idx[curr_circuit_idx];

    EvalIntermediateBucketParallel(composed_circuit.circuits[curr_circuit_idx], curr_inp_keys.GetArray(), output_keys[component_out_start_pos]);
    // EvalIntermediateBucketSerial(composed_circuit.circuits[curr_circuit_idx], curr_inp_keys.GetArray(), output_keys[component_out_start_pos]);

  }
}

void DuploEvaluator::EvalInputBucketsParallel(std::vector<std::pair<std::string, uint32_t>>& components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& input_keys, std::vector<BYTEArrayVector>& output_keys) {

  uint32_t exec_curr_input_buckets_start = 0;
  for (int l = 0; l < components_from; ++l) {
    std::string component_name = std::get<0>(components[l]);
    Circuit& circuit = string_to_circuit_map[component_name];
    exec_curr_input_buckets_start += circuit.num_inp_wires;
  }

  uint32_t num_components = components_to - components_from;
  GarblingHandler gh;
  for (uint64_t l = 0; l < num_components; ++l) {
    uint32_t curr_component = components_from + l;
    std::string component_name = std::get<0>(components[curr_component]);
    uint32_t component_num = std::get<1>(components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];

    uint32_t garbled_table_size = GarbledCircuit::TotalTableSize(circuit);
    uint32_t solderings_size = EvalGarbledCircuit::SolderingsSize(circuit);

    BYTEArrayVector read_bucket;
    BYTEArrayVector read_solderings;
    BYTEArrayVector read_auths_input;
    BYTEArrayVector read_auths_input_solderings;
    BYTEArrayVector read_auths_input_delta_soldering;
    BYTEArrayVector read_auths_inputs_ids;

    persistent_storage.ReadBuckets(component_name, TABLES, component_num, 1, read_bucket);
    persistent_storage.ReadBuckets(component_name, SOLDERINGS, component_num, 1, read_solderings);
    persistent_storage.ReadBuckets(AUTHS_INPUT_PREFIX, AUTHS, exec_curr_input_buckets_start, circuit.num_inp_wires, read_auths_input);
    persistent_storage.ReadBuckets(AUTHS_INPUT_PREFIX, AUTHS_SOLDERINGS, exec_curr_input_buckets_start, circuit.num_inp_wires, read_auths_input_solderings);
    persistent_storage.ReadBuckets(AUTHS_INPUT_PREFIX, AUTHS_DELTA_SOLDERINGS, curr_component, 1, read_auths_input_delta_soldering);
    persistent_storage.ReadBuckets(AUTHS_INPUT_PREFIX, AUTHS_IDS, exec_curr_input_buckets_start, circuit.num_inp_wires, read_auths_inputs_ids);
    exec_curr_input_buckets_start += circuit.num_inp_wires;

    uint32_t bucket_size = read_bucket.entry_size / garbled_table_size;
    uint32_t auth_size = read_auths_input.entry_size / (2 * CSEC_BYTES);

    uint8_t soldered_input[CSEC_BYTES];
    for (int j = 0; j < circuit.num_inp_wires; ++j) {
      for (uint32_t a = 0; a < auth_size; ++a) {

        std::copy(input_keys[l][j], input_keys[l][j + 1], soldered_input);
        if (GetLSB(soldered_input)) {
          XOR_128(soldered_input, read_auths_input_delta_soldering.GetArray());
        }

        XOR_128(soldered_input, read_auths_input_solderings[j] + a * CSEC_BYTES);
        uint32_t id = *(uint32_t*) (read_auths_inputs_ids[j] + a * sizeof(uint32_t));

        if (!VerifyAuth(soldered_input, read_auths_input[j] + 2 * a * CSEC_BYTES, read_auths_input[j] + (2 * a + 1) * CSEC_BYTES, id, gh.key_schedule)) {
          std::cout << "Abort, wrong input keys detected by input buckets!" << std::endl;
          throw std::runtime_error("Abort, wrong input keys detected by input buckets!");
        }
      }
    }

    std::vector<BYTEArrayVector> cand_outputs(bucket_size, BYTEArrayVector(circuit.num_out_wires, CSEC_BYTES));
    std::vector<std::future<void>> futures;
    for (uint32_t i = 0; i < bucket_size; ++i) {

      futures.emplace_back(std::async(std::launch::async, [this, &read_bucket, &read_solderings, &gh, &input_keys, &components, &cand_outputs, l, curr_component, i, garbled_table_size, solderings_size]() {

        Circuit& circuit = string_to_circuit_map[std::get<0>(components[curr_component])];

        uint8_t* curr_garbled_tables = read_bucket.GetArray() + i * garbled_table_size;
        uint8_t* curr_solderings = read_solderings.GetArray() + i * solderings_size;

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

      output_keys.emplace_back(BYTEArrayVector(circuit.num_out_wires, CSEC_BYTES));
      std::copy(cand_outputs[0][0], cand_outputs[0][circuit.num_out_wires], output_keys[l].GetArray());
    } else {
      //Error handling, evaluate output authenticators, etc etc
      std::cout << "Problem! Bucket " << l << " doesn't output the same!" << std::endl;
    }
  }
}

void DuploEvaluator::EvalInputBucketsSerial(std::vector<std::pair<std::string, uint32_t>>& components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& input_keys, std::vector<BYTEArrayVector>& output_keys) {

  uint32_t exec_curr_input_buckets_start = 0;
  for (int l = 0; l < components_from; ++l) {
    std::string component_name = std::get<0>(components[l]);
    Circuit& circuit = string_to_circuit_map[component_name];
    exec_curr_input_buckets_start += circuit.num_inp_wires;
  }

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
    BYTEArrayVector read_auths_input;
    BYTEArrayVector read_auths_input_solderings;
    BYTEArrayVector read_auths_input_delta_soldering;
    BYTEArrayVector read_auths_inputs_ids;

    persistent_storage.ReadBuckets(component_name, TABLES, component_num, 1, read_bucket);
    persistent_storage.ReadBuckets(component_name, SOLDERINGS, component_num, 1, read_solderings);
    persistent_storage.ReadBuckets(AUTHS_INPUT_PREFIX, AUTHS, exec_curr_input_buckets_start, circuit.num_inp_wires, read_auths_input);
    persistent_storage.ReadBuckets(AUTHS_INPUT_PREFIX, AUTHS_SOLDERINGS, exec_curr_input_buckets_start, circuit.num_inp_wires, read_auths_input_solderings);
    persistent_storage.ReadBuckets(AUTHS_INPUT_PREFIX, AUTHS_DELTA_SOLDERINGS, curr_component, 1, read_auths_input_delta_soldering);
    persistent_storage.ReadBuckets(AUTHS_INPUT_PREFIX, AUTHS_IDS, exec_curr_input_buckets_start, circuit.num_inp_wires, read_auths_inputs_ids);
    exec_curr_input_buckets_start += circuit.num_inp_wires;

    uint32_t bucket_size = read_bucket.entry_size / garbled_table_size;
    uint32_t auth_size = read_auths_input.entry_size / (2 * CSEC_BYTES);

    uint8_t soldered_input[CSEC_BYTES];
    for (int j = 0; j < circuit.num_inp_wires; ++j) {
      for (uint32_t a = 0; a < auth_size; ++a) {

        std::copy(input_keys[l][j], input_keys[l][j + 1], soldered_input);
        if (GetLSB(soldered_input)) {
          XOR_128(soldered_input, read_auths_input_delta_soldering.GetArray());
        }

        XOR_128(soldered_input, read_auths_input_solderings[j] + a * CSEC_BYTES);
        uint32_t id = *(uint32_t*) (read_auths_inputs_ids[j] + a * sizeof(uint32_t));

        if (!VerifyAuth(soldered_input, read_auths_input[j] + 2 * a * CSEC_BYTES, read_auths_input[j] + (2 * a + 1) * CSEC_BYTES, id, gh.key_schedule)) {
          std::cout << "Abort, wrong input keys detected by input buckets!" << std::endl;
          throw std::runtime_error("Abort, wrong input keys detected by input buckets!");
        }
      }
    }

    bool success = true;
    std::vector<BYTEArrayVector> cand_outputs(bucket_size, BYTEArrayVector(circuit.num_out_wires, CSEC_BYTES));
    for (uint32_t i = 0; i < bucket_size; ++i) {

      Circuit& circuit = string_to_circuit_map[std::get<0>(components[curr_component])];

      uint8_t* curr_garbled_tables = read_bucket.GetArray() + i * garbled_table_size;
      uint8_t* curr_solderings = read_solderings.GetArray() + i * solderings_size;

      gh.EvalGarbledCircuitSolderings(input_keys[l].GetArray(), circuit, curr_garbled_tables, curr_solderings, cand_outputs[i].GetArray());

      if (i != 0) {
        if (!std::equal(cand_outputs[0][0], cand_outputs[0][circuit.num_out_wires], cand_outputs[i].GetArray())) {
          success = false;
        }
      }
    }
    if (success) {
      output_keys.emplace_back(BYTEArrayVector(circuit.num_out_wires, CSEC_BYTES));
      std::copy(cand_outputs[0][0], cand_outputs[0][circuit.num_out_wires], output_keys[l].GetArray());
    } else {
      //Error handling, evaluate output authenticators, etc etc
      std::cout << "Problem! Bucket " << l << " doesn't output the same!" << std::endl;
    }
  }
}

void DuploEvaluator::EvalIntermediateBucketSerial(std::pair<std::string, uint32_t>& component, uint8_t input_keys[], uint8_t output_keys[]) {

  std::string component_name = std::get<0>(component);
  uint32_t component_num = std::get<1>(component);
  Circuit& circuit = string_to_circuit_map[component_name];

  GarblingHandler gh;
  uint32_t garbled_table_size = GarbledCircuit::TotalTableSize(circuit);
  uint32_t solderings_size = EvalGarbledCircuit::SolderingsSize(circuit);

  BYTEArrayVector read_bucket;
  BYTEArrayVector read_solderings;

  persistent_storage.ReadBuckets(component_name, TABLES, component_num, 1, read_bucket);
  persistent_storage.ReadBuckets(component_name, SOLDERINGS, component_num, 1, read_solderings);

  uint32_t bucket_size = read_bucket.entry_size / garbled_table_size;

  bool success = true;
  std::vector<BYTEArrayVector> cand_outputs(bucket_size, BYTEArrayVector(circuit.num_out_wires, CSEC_BYTES));
  for (uint32_t i = 0; i < bucket_size; ++i) {

    uint8_t* curr_garbled_tables = read_bucket.GetArray() + i * garbled_table_size;
    uint8_t* curr_solderings = read_solderings.GetArray() + i * solderings_size;

    gh.EvalGarbledCircuitSolderings(input_keys, circuit, curr_garbled_tables, curr_solderings, cand_outputs[i].GetArray());

    if (i != 0) {
      if (!std::equal(cand_outputs[0][0], cand_outputs[0][circuit.num_out_wires], cand_outputs[i].GetArray())) {
        success = false;
      }
    }
  }
  if (success) {
    std::copy(cand_outputs[0][0], cand_outputs[0][circuit.num_out_wires], output_keys);
  } else {
    //Error handling, evaluate output authenticators, etc etc
    std::cout << "Problem! Bucket doesn't output the same!" << std::endl;
  }
}

void DuploEvaluator::EvalIntermediateBucketParallel(std::pair<std::string, uint32_t>& component, uint8_t input_keys[], uint8_t output_keys[]) {

  std::string component_name = std::get<0>(component);
  uint32_t component_num = std::get<1>(component);
  Circuit& circuit = string_to_circuit_map[component_name];

  GarblingHandler gh;
  uint32_t garbled_table_size = GarbledCircuit::TotalTableSize(circuit);
  uint32_t solderings_size = EvalGarbledCircuit::SolderingsSize(circuit);

  BYTEArrayVector read_bucket;
  BYTEArrayVector read_solderings;

  persistent_storage.ReadBuckets(component_name, TABLES, component_num, 1, read_bucket);
  persistent_storage.ReadBuckets(component_name, SOLDERINGS, component_num, 1, read_solderings);

  uint32_t bucket_size = read_bucket.entry_size / garbled_table_size;

  std::vector<BYTEArrayVector> cand_outputs(bucket_size, BYTEArrayVector(circuit.num_out_wires, CSEC_BYTES));

  std::vector<std::future<void>> futures;
  for (uint32_t i = 0; i < bucket_size; ++i) {

    futures.emplace_back(std::async(std::launch::async, [this, &read_bucket, &read_solderings, &gh, &circuit, &cand_outputs, input_keys, i, garbled_table_size, solderings_size]() {

      uint8_t* curr_garbled_tables = read_bucket.GetArray() + i * garbled_table_size;
      uint8_t* curr_solderings = read_solderings.GetArray() + i * solderings_size;

      gh.EvalGarbledCircuitSolderings(input_keys, circuit, curr_garbled_tables, curr_solderings, cand_outputs[i].GetArray());
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
    std::copy(cand_outputs[0][0], cand_outputs[0][circuit.num_out_wires], output_keys);
  } else {
    //Error handling, evaluate output authenticators, etc etc
    std::cout << "Problem! Bucket doesn't output the same!" << std::endl;
  }
}

bool DuploEvaluator::DecommitOutPermBits(CommonTools& exec_common_tools, std::vector<std::pair<std::string, uint32_t>>& output_components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& output_decodings) {

  uint32_t exec_num_components = components_to - components_from;

  uint32_t num_eval_total_outputs = 0;
  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = components_from + i;
    std::string component_name = std::get<0>(output_components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];
    num_eval_total_outputs += circuit.num_eval_out_wires;
  }

  BYTEArrayVector exec_res_share(num_eval_total_outputs, BIT_CODEWORD_BYTES);

  uint32_t eval_inc_pos = 0;
  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = components_from + i;
    std::string component_name = std::get<0>(output_components[curr_component]);
    uint32_t component_num = std::get<1>(output_components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];

    BYTEArrayVector component_aux_data;
    persistent_storage.ReadBuckets(component_name, AUXDATA, component_num, 1, component_aux_data);

    for (int j = circuit.eval_out_wires_start; j < circuit.eval_out_wires_stop; ++j) {
      uint32_t curr_bit_pos = eval_inc_pos + j - circuit.eval_out_wires_start;
      std::copy(EvalGarbledCircuit::out_bit_share(circuit, component_aux_data[0], j),
                EvalGarbledCircuit::out_bit_share(circuit, component_aux_data[0], j + 1),
                exec_res_share[curr_bit_pos]);
    }
    eval_inc_pos += circuit.num_eval_out_wires;
  }

  BYTEArrayVector exec_res(BITS_TO_BYTES(num_eval_total_outputs), 1);
  exec_common_tools.chan.ReceiveBlocking(exec_res.GetArray(), exec_res.size);

  BitCommitReceiver bit_commit_rec(exec_common_tools, commit_seed_OTs[CODEWORD_BITS], commit_seed_choices[CODEWORD_BYTES]);
  if (!bit_commit_rec.BatchDecommit(exec_res_share.GetArray(), num_eval_total_outputs, exec_res.GetArray())) {
    return false;
  }

  eval_inc_pos = 0;
  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = components_from + i;
    std::string component_name = std::get<0>(output_components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];

    output_decodings.emplace_back(BYTEArrayVector(BITS_TO_BYTES(circuit.num_eval_out_wires), 1));
    for (int j = 0; j < circuit.num_eval_out_wires; ++j) {
      SetBit(j, GetBit(eval_inc_pos + j, exec_res.GetArray()), output_decodings[i].GetArray());
    }
    eval_inc_pos += circuit.num_eval_out_wires;
  }

  return true;
}

void DuploEvaluator::InpBucketCommitAndCutAndChoose(CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_num_total_garbled, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_circuits_from, uint32_t exec_eval_circuits_to, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data) {

  uint32_t num_inp_keys, num_out_keys, num_deltas, num_commit_keys, num_base_keys, input_keys_idx, output_keys_idx, deltas_idx;
  ComputeIndices(exec_num_total_garbled, circuit, num_inp_keys, num_out_keys, num_deltas, num_commit_keys, num_base_keys, input_keys_idx, output_keys_idx, deltas_idx);

  CommitReceiver commit_rec(exec_common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());
  BitCommitReceiver bit_commit_rec(exec_common_tools, commit_seed_OTs[CODEWORD_BITS], commit_seed_choices[CODEWORD_BYTES]);

  BYTEArrayVector commit_keys_share(num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector commit_perm_bits_share(num_base_keys, BIT_CODEWORD_BYTES);

  //Commit to keys
  if (!commit_rec.Commit(num_commit_keys, commit_keys_share, exec_prg_counter, deltas_idx)) {
    std::cout << "Abort, key commit failed!" << std::endl;;
    throw std::runtime_error("Abort, key commit failed!");
  }

  if (!bit_commit_rec.Commit(num_base_keys, commit_perm_bits_share, exec_prg_counter)) {
    std::cout << "Abort, perm_bit commit failed!" << std::endl;;
    throw std::runtime_error("Abort, perm_bit commit failed!");
  }

  BYTEArrayVector inp_wire_commit_corrections(num_inp_keys, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(inp_wire_commit_corrections.GetArray(), inp_wire_commit_corrections.size);

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

  BYTEArrayVector cnc_perm_bits_share(cnc_num_base_keys, BIT_CODEWORD_BYTES);
  BYTEArrayVector cnc_keys_share(cnc_num_commit_keys, CODEWORD_BYTES);

  //Receive postulated perm_bit values
  BYTEArrayVector cnc_commit_perm_bits(BITS_TO_BYTES(cnc_num_base_keys), 1);
  exec_common_tools.chan.ReceiveBlocking(cnc_commit_perm_bits.GetArray(), cnc_commit_perm_bits.size);

  uint32_t current_check_circuit_idx = 0;
  for (int i = 0; i < exec_num_total_garbled; ++i) {
    if (GetBit(i, cnc_check_circuits.data())) { //Checked circuit

      //Add delta
      std::copy(commit_keys_share[deltas_idx + i], commit_keys_share[deltas_idx + (i + 1)], cnc_keys_share[cnc_deltas_idx + current_check_circuit_idx]);

      //Add inputs
      std::copy(commit_keys_share[input_keys_idx + i],
                commit_keys_share[input_keys_idx + (i + 1)],
                cnc_keys_share[cnc_input_keys_idx + current_check_circuit_idx]);

      //Add input permutation bits
      std::copy(commit_perm_bits_share[input_keys_idx + i],
                commit_perm_bits_share[input_keys_idx + (i + 1)],
                cnc_perm_bits_share[cnc_input_keys_idx + current_check_circuit_idx]);

      if (GetBit(cnc_input_keys_idx + current_check_circuit_idx, cnc_commit_perm_bits.GetArray())) {
        XOR_CodeWords(cnc_keys_share[cnc_input_keys_idx + current_check_circuit_idx],
                      cnc_keys_share[cnc_deltas_idx + current_check_circuit_idx]);
      }

      ++current_check_circuit_idx;
    }
  }

  //Batch decommit these values
  if (!bit_commit_rec.BatchDecommit(cnc_perm_bits_share.GetArray(), cnc_num_base_keys, cnc_commit_perm_bits.GetArray())) {
    std::cout << "Abort, cut-and-choose bit decommit failed!" << std::endl;;
    throw std::runtime_error("Abort, cut-and-choose bit decommit failed!");
  }

  BYTEArrayVector cnc_keys(cnc_num_commit_keys, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(cnc_keys.GetArray(), cnc_keys.size);
  if (!commit_rec.BatchDecommit(cnc_keys_share.GetArray(), cnc_num_commit_keys, cnc_keys.GetArray())) {
    std::cout << "Abort, cut-and-choose decommit failed!" << std::endl;
    throw std::runtime_error("Abort, cut-and-choose decommit failed!");
  }

  GarblingHandler gh;
  std::vector<EvalGarbledCircuit> cnc_garbled_circuits(num_checked_circuits, EvalGarbledCircuit(circuit));

  BYTEArrayVector cnc_garb_circuit_hashes(num_checked_circuits, CSEC_BYTES);

  uint8_t curr_hash_val[CSEC_BYTES];

  current_check_circuit_idx = 0; //reset counter
  uint32_t current_eval_circuit_idx = exec_eval_circuits_from;
  bool completed_eval_copy = false;
  for (int i = 0; i < exec_num_total_garbled; ++i) {
    if (GetBit(i, cnc_check_circuits.data())) {

      //Check that lsb(Delta) == 1
      if (!GetLSB(cnc_keys[cnc_deltas_idx + current_check_circuit_idx])) {
        std::cout << "Abort, lsb(delta) was incorrect!" << std::endl;
        throw std::runtime_error("Abort, lsb(delta) was incorrect!");
      }

      //Check that lsb(base_inp_key)==0
      if (GetLSB(cnc_keys[cnc_input_keys_idx + current_check_circuit_idx]) ^
          GetBit(cnc_input_keys_idx + current_check_circuit_idx, cnc_commit_perm_bits.GetArray())) {
        std::cout << "Abort, lsb(base_inp_key) != 0" << std::endl;
        throw std::runtime_error("Abort, lsb(base_inp_key) != 0");
      }

      gh.GarbleInpBucket(curr_hash_val, cnc_keys[cnc_deltas_idx + current_check_circuit_idx], 0);

      XOR_128(curr_hash_val, cnc_keys[cnc_input_keys_idx + current_check_circuit_idx]);

      if (!std::equal(curr_hash_val, curr_hash_val + CSEC_BYTES, inp_wire_commit_corrections[i])) {
        std::cout << "Abort, garbled circuit wrong output commits!" << std::endl;
        throw std::runtime_error("Abort, garbled circuit wrong output commits!");
      }

      ++current_check_circuit_idx;
    } else if (current_eval_circuit_idx < exec_eval_circuits_to) {

      //Copy Delta
      std::copy(commit_keys_share[deltas_idx + i], commit_keys_share[deltas_idx + (i + 1)], aux_garbled_circuits_data[current_eval_circuit_idx].delta_share());

      //Copy inputs
      std::copy(commit_keys_share[input_keys_idx + i],
                commit_keys_share[input_keys_idx + (i + 1)],
                aux_garbled_circuits_data[current_eval_circuit_idx].inp_key_share());

      //Copy input permutation bits
      std::copy(commit_perm_bits_share[input_keys_idx + i],
                commit_perm_bits_share[input_keys_idx + (i + 1)],
                aux_garbled_circuits_data[current_eval_circuit_idx].inp_bit_share());

      std::copy(inp_wire_commit_corrections[i], inp_wire_commit_corrections[(i + 1)], aux_garbled_circuits_data[current_eval_circuit_idx].inp_soldering());
      ++current_eval_circuit_idx;
    } else {
      completed_eval_copy = true;
    }
  }

  if (!completed_eval_copy) {
    std::cout << "Problem. Not enough eval circuits! Params should be set so this never occurs" << std::endl;
  }
}

void DuploEvaluator::InpBucketReceiveSolderings(std::vector<std::pair<std::string, uint32_t>>& input_components, CommonTools & exec_common_tools, Circuit & inp_bucket_circuit, uint32_t bucket_size, std::vector<uint32_t>& permuted_eval_ids_inv, uint32_t exec_components_from, uint32_t exec_components_to, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data) {

  uint32_t exec_num_components = exec_components_to - exec_components_from;
  uint32_t exec_num_total_const_inputs = 0;
  std::vector<uint32_t> const_inp_pos;
  for (int i = 0; i < exec_num_components; ++i) {
    uint32_t curr_component = exec_components_from + i;
    std::string component_name = std::get<0>(input_components[curr_component]);
    Circuit& circuit = string_to_circuit_map[component_name];

    const_inp_pos.emplace_back(exec_num_total_const_inputs);

    exec_num_total_const_inputs += circuit.num_const_inp_wires;
  }

  uint32_t exec_prior_const_inp_wires = 0;
  for (int i = 0; i < exec_components_from; ++i) {
    std::string component_name = std::get<0>(input_components[i]);
    Circuit& circuit = string_to_circuit_map[component_name];
    exec_prior_const_inp_wires += circuit.num_const_inp_wires;
  }

  // uint64_t garbled_table_size = GarbledCircuit::TotalTableSize(circuit);
  uint64_t solderings_size = EvalGarbledCircuit::SolderingsSize(inp_bucket_circuit);
  uint64_t total_eval_aux_size = EvalGarbledCircuit::TotalAuxDataSize(inp_bucket_circuit);

  uint32_t num_solderings = exec_num_total_const_inputs * bucket_size;
  BYTEArrayVector exec_permuted_aux_info(num_solderings, total_eval_aux_size);
  BYTEArrayVector exec_write_solderings(num_solderings, solderings_size);

  uint32_t solder_num_inp_keys, solder_num_out_keys, solder_num_deltas, solder_num_commit_keys, solder_num_base_keys, solder_inp_keys_idx, solder_out_keys_idx, solder_deltas_idx;
  ComputeIndices(num_solderings, inp_bucket_circuit, solder_num_inp_keys, solder_num_out_keys, solder_num_deltas, solder_num_commit_keys, solder_num_base_keys, solder_inp_keys_idx, solder_out_keys_idx, solder_deltas_idx);

  BYTEArrayVector solder_keys_share(solder_num_commit_keys, CODEWORD_BYTES);
  BYTEArrayVector solder_perm_bits_share(solder_num_base_keys, BIT_CODEWORD_BYTES);

  BYTEArrayVector solder_commit_perm_bits(BITS_TO_BYTES(solder_num_base_keys), 1);
  //Receive postulated perm_bits values
  exec_common_tools.chan.ReceiveBlocking(solder_commit_perm_bits.GetArray(), solder_commit_perm_bits.size);

  //Receive the postulated solderings and check correctness using batch decommit
  BYTEArrayVector solder_keys(solder_num_commit_keys, CSEC_BYTES);
  exec_common_tools.chan.ReceiveBlocking(solder_keys.GetArray(), solder_keys.size);

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
        std::copy(aux_garbled_circuits_data[permuted_eval_ids_inv[global_inp_circuit_index]].GetAuxArray(), aux_garbled_circuits_data[permuted_eval_ids_inv[global_inp_circuit_index]].GetAuxArray() + total_eval_aux_size, exec_permuted_aux_info[curr_inp_bucket_idx]);

        //Copy Delta soldering
        std::copy(EvalGarbledCircuit::delta_share(circuit, component_aux_data.GetArray()),
                  EvalGarbledCircuit::delta_share(circuit, component_aux_data.GetArray()) + CODEWORD_BYTES,
                  solder_keys_share[solder_deltas_idx + curr_inp_bucket_idx]);
        XOR_CodeWords(solder_keys_share[solder_deltas_idx + curr_inp_bucket_idx],
                      EvalGarbledCircuit::delta_share(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));

        //Copy input soldering
        std::copy(EvalGarbledCircuit::inp_key_share(circuit, component_aux_data.GetArray(), j),
                  EvalGarbledCircuit::inp_key_share(circuit, component_aux_data.GetArray(), j + 1),
                  solder_keys_share[solder_inp_keys_idx + curr_inp_bucket_idx]);
        XOR_CodeWords(solder_keys_share[solder_inp_keys_idx + curr_inp_bucket_idx],
                      EvalGarbledCircuit::inp_key_share(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));

        //If xor of perm bits == 1 we XOR delta onto the soldering
        if (GetBit(solder_inp_keys_idx + curr_inp_bucket_idx, solder_commit_perm_bits.GetArray())) {

          XOR_CodeWords(solder_keys_share[solder_inp_keys_idx + curr_inp_bucket_idx], EvalGarbledCircuit::delta_share(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));
        }

        //Add input permutation bit soldering decommit
        std::copy(EvalGarbledCircuit::inp_bit_share(circuit, component_aux_data.GetArray(), j),
                  EvalGarbledCircuit::inp_bit_share(circuit, component_aux_data.GetArray(), j + 1),
                  solder_perm_bits_share[solder_inp_keys_idx + curr_inp_bucket_idx]);
        XOR_BitCodeWords(solder_perm_bits_share[solder_inp_keys_idx + curr_inp_bucket_idx],
                         EvalGarbledCircuit::inp_bit_share(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));


        //Copy curr delta soldering
        std::copy(solder_keys[solder_deltas_idx + curr_inp_bucket_idx],
                  solder_keys[solder_deltas_idx + curr_inp_bucket_idx + 1],
                  EvalGarbledCircuit::delta_soldering(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]));

        //Add input solderings to the inp_wire_corrections already in inp_soldering
        XOR_128(EvalGarbledCircuit::inp_soldering(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]), solder_keys[solder_inp_keys_idx + curr_inp_bucket_idx]);

        //Copy curr soldering info for writing to disc
        std::copy(EvalGarbledCircuit::inp_soldering(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]),
                  EvalGarbledCircuit::inp_soldering(inp_bucket_circuit, exec_permuted_aux_info[curr_inp_bucket_idx]) + solderings_size, exec_write_solderings[curr_inp_bucket_idx]);
      }
    }
  }

  BitCommitReceiver bit_commit_rec(exec_common_tools, commit_seed_OTs[CODEWORD_BITS], commit_seed_choices[CODEWORD_BYTES]);
  //Batch decommit these values
  if (!bit_commit_rec.BatchDecommit(solder_perm_bits_share.GetArray(), solder_num_base_keys, solder_commit_perm_bits.GetArray())) {
    std::cout << "Abort, soldering bit decommit failed!" << std::endl;;
    throw std::runtime_error("Abort, soldering bit decommit failed!");
  }

  CommitReceiver commit_rec(exec_common_tools, commit_seed_OTs.GetArray(), commit_seed_choices.GetArray());
  if (!commit_rec.BatchDecommit(solder_keys_share.GetArray(), solder_num_commit_keys, solder_keys.GetArray())) {
    std::cout << "Abort, soldering decommit failed!" << std::endl;
    throw std::runtime_error("Abort, soldering decommit failed!");
  }

  //////////////////////////////Write to Disc/////////////////////////////////

  uint64_t exec_solderings_write_pos = exec_prior_const_inp_wires * solderings_size * bucket_size;
  // uint64_t exec_auxdata_write_pos = exec_write_head_auxdata.size * exec_common_tools.exec_id;

  persistent_storage.WriteBuckets(EVAL_INP_BUCKET_PREFIX, SOLDERINGS, exec_prior_const_inp_wires, exec_num_total_const_inputs, exec_write_solderings.GetArray(), exec_solderings_write_pos, exec_write_solderings.size, bucket_size);
  // persistent_storage.WriteBuckets(EVAL_INP_BUCKET_PREFIX, AUXDATA, exec_buckets_from, exec_num_buckets, exec_write_head_auxdata.GetArray(), exec_auxdata_write_pos, exec_write_head_auxdata.size, 1);
}