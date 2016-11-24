#ifndef DUPLO_DUPLOEVAL_H_
#define DUPLO_DUPLOEVAL_H_

#include "duplo/duplo.h"
#include "dot/alsz-dot-ext-rec.h"
#include "commit/commit-scheme-rec.h"
#include "garbling/eval-garbled-circuit.h"
#include "commit/commit-scheme-rec.h"
#include "commit/bit-commit-scheme-rec.h"

class DuploEvaluator : public Duplo {
public:
  DuploEvaluator(CommonTools& common_tools, uint32_t num_max_parallel_execs = 1);

  void Setup();

  void PreprocessComponentType(std::string component_type, Circuit& circuit, uint32_t num_buckets, uint32_t num_parallel_execs = 1, BucketType bucket_type = SINGLE);

  void SolderGarbledComponents(std::string& res_component, ComposedCircuit& composed_circuit, uint32_t num_parallel_execs = 1);

  void PrepareComponents(std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t num_parallel_execs = 1);

  void EvalComponents(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& eval_output_keys, uint32_t num_parallel_execs = 1, bool send_output_keys = true);

  void EvalComposedComponents(std::string& res_component, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& eval_output_keys, uint32_t num_parallel_execs = 1);

  void DecodeKeys(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<BYTEArrayVector>& output_keys, std::vector<std::vector<uint8_t>>& outputs, uint32_t num_parallel_execs = 1);

  BYTEArrayVector commit_seed_OTs;
  BYTEArrayVector commit_seed_choices;


private:
  ALSZDOTExtRec ot_rec;

  void CommitReceiveAndCutAndChoose(CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_num_total_garbled, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_circuits_from, uint32_t exec_eval_circuits_to, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data, BYTEArrayVector& eval_hash);

  void BucketAndReceiveEvalCircuits(std::string component_type, CommonTools& exec_common_tools, Circuit& circuit, uint32_t bucket_size, std::vector<uint32_t>& permuted_eval_ids_inv, uint32_t exec_buckets_from, uint32_t exec_buckets_to, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data, BYTEArrayVector& eval_hash);

  void CommitAuthAndCutAndChoose(CommonTools& exec_common_tools, uint32_t exec_num_auths, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_auths_from, uint32_t exec_eval_auths_to, std::vector<BYTEArrayVector>& eval_auths, BYTEArrayVector& aux_auth_data, std::vector<uint32_t>& aux_auth_ids, uint8_t aux_auth_delta_data[], std::tuple<std::mutex&, std::condition_variable&, bool&>& delta_signal);

  void BucketAllAuths(CommonTools& exec_common_tools, uint32_t auth_size, std::vector<uint32_t>& permuted_eval_ids_inv, std::vector<int>& session_circuit_buckets_from, std::vector<int>& session_circuit_buckets_to, std::vector<BYTEArrayVector>& eval_auths, BYTEArrayVector& aux_auth_data, std::vector<uint32_t>& aux_auth_ids, uint8_t aux_auth_delta_data[], std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t input_components_from, uint32_t input_components_to, std::vector<uint32_t>& input_components_auth_start_pos);

  void ReceiveAndStoreSolderings(CommonTools& exec_common_tools, std::string& res_component, ComposedCircuit& composed_circuit, uint32_t inp_wire_components_from, uint32_t inp_wire_components_to);
  
  void PrepareInputBuckets(std::vector<std::pair<std::string, uint32_t>>& input_components, uint num_parallel_execs = 1);

  void PreprocessEvalInputOTs(std::vector<std::pair<std::string, uint32_t>>& input_components);

  bool DecommitEvalInputPermBits(CommonTools& exec_common_tools, std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t components_from, uint32_t components_to);

  void EvalComposedComponent(CommonTools& exec_common_tools, std::string& res_component, uint32_t components_from, uint32_t components_to, uint32_t current_layer_start_idx, BYTEArrayVector& output_keys);

  void EvalInputBucketsParallel(std::vector<std::pair<std::string, uint32_t>>& components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& input_keys, std::vector<BYTEArrayVector>& output_keys);

  void EvalInputBucketsSerial(std::vector<std::pair<std::string, uint32_t>>& components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& input_keys, std::vector<BYTEArrayVector>& output_keys);

  void EvalIntermediateBucketParallel(std::pair<std::string, uint32_t>& component, uint8_t input_keys[], uint8_t output_keys[]);

  void EvalIntermediateBucketSerial(std::pair<std::string, uint32_t>& component, uint8_t input_keys[], uint8_t output_keys[]);

  bool DecommitOutPermBits(CommonTools& exec_common_tools, std::vector<std::pair<std::string, uint32_t>>& output_components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& output_decodings);

  void InpBucketCommitAndCutAndChoose(CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_num_total_garbled, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_circuits_from, uint32_t exec_eval_circuits_to, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data);

  void InpBucketReceiveSolderings(std::vector<std::pair<std::string, uint32_t>>& input_components, CommonTools& exec_common_tools, Circuit& inp_bucket_circuit, uint32_t bucket_size, std::vector<uint32_t>& permuted_eval_ids_inv, uint32_t exec_components_from, uint32_t exec_components_to, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data);
};

#endif /* DUPLO_DUPLOEVAL_H_ */