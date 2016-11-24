#ifndef DUPLO_DUPLOCONST_H_
#define DUPLO_DUPLOCONST_H_

#include "duplo/duplo.h"
#include "dot/alsz-dot-ext-snd.h"
#include "garbling/const-garbled-circuit.h"
#include "commit/bit-commit-scheme-snd.h"
#include "commit/commit-scheme-snd.h"

class DuploConstructor : public Duplo {
public:
  DuploConstructor(CommonTools& common_tools, uint32_t num_max_parallel_execs = 1);

  void Setup();

  void PreprocessComponentType(std::string component_type, Circuit& circuit, uint32_t num_buckets, uint32_t num_parallel_execs = 1, BucketType bucket_type = SINGLE);

  void SolderGarbledComponents(std::string& res_component, ComposedCircuit& composed_circuit, uint32_t num_parallel_execs = 1);

  void PrepareComponents(std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t num_parallel_execs = 1);

  void EvalComponents(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& const_output_keys, uint32_t num_parallel_execs = 1, bool receive_output_keys = true);

  void EvalComposedComponents(std::string& res_component, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& const_output_keys, uint32_t num_parallel_execs = 1);

  void DecodeKeys(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<BYTEArrayVector>& output_keys, std::vector<std::vector<uint8_t>>& outputs, uint32_t num_parallel_execs = 1);

  BYTEArrayVector commit_seed_OTs0;
  BYTEArrayVector commit_seed_OTs1;

private:
  ALSZDOTExtSnd ot_snd;

  void CommitGarbleAndCutAndChoose(CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_num_total_garbled, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_circuits_from, uint32_t exec_eval_circuits_to, std::vector<ConstGarbledCircuit>& aux_garbled_circuits_data);

  void BucketAndSendEvalCircuits(std::string component_type, CommonTools& exec_common_tools, Circuit& circuit, uint32_t bucket_size, std::vector<uint32_t>& permuted_eval_ids_inv, uint32_t exec_buckets_from, uint32_t exec_buckets_to, std::vector<ConstGarbledCircuit>& aux_garbled_circuits_data);

  void ComputeAndSendSolderings(CommonTools& exec_common_tools, std::string& res_component, ComposedCircuit& composed_circuit, uint32_t inp_wire_components_from, uint32_t inp_wire_components_to);

  void CommitAuthAndCutAndChoose(CommonTools& exec_common_tools, uint32_t exec_num_auths, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_auths_from, uint32_t exec_eval_auths_to, std::vector<BYTEArrayVector>& aux_auth_data, BYTEArrayVector& aux_auth_delta_data, std::tuple<std::mutex&, std::condition_variable&, bool&>& delta_signal);

  void BucketAllAuths(CommonTools& exec_common_tools, uint32_t auth_size, std::vector<uint32_t>& permuted_eval_ids_inv, std::vector<int>& session_circuit_buckets_from, std::vector<int>& session_circuit_buckets_to, std::vector<BYTEArrayVector>& aux_auth_data, BYTEArrayVector& aux_auth_delta_data, std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t input_components_from, uint32_t input_components_to, std::vector<uint32_t>& input_components_auth_start_pos);

  void PrepareInputBuckets(std::vector<std::pair<std::string, uint32_t>>& input_components, uint num_parallel_execs = 1);

  void PreprocessEvalInputOTs(std::vector<std::pair<std::string, uint32_t>>& input_components);

  void DecommitEvalInputPermBits(CommonTools& exec_common_tools, std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t components_from, uint32_t components_to);

  void DecommitOutPermBits(CommonTools& exec_common_tools, std::vector<std::pair<std::string, uint32_t>>& output_components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& output_decodings);

  void InpBucketCommitAndCutAndChoose(CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_num_total_garbled, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_circuits_from, uint32_t exec_eval_circuits_to, std::vector<ConstGarbledCircuit>& aux_garbled_circuits_data);

  void InpBucketSendSolderings(std::vector<std::pair<std::string, uint32_t>>& input_components, CommonTools& exec_common_tools, Circuit& inp_bucket_circuit, uint32_t bucket_size, std::vector<uint32_t>& permuted_eval_ids_inv, uint32_t exec_components_from, uint32_t exec_components_to, std::vector<ConstGarbledCircuit>& aux_garbled_circuits_data);
};

#endif /* DUPLO_DUPLOCONST_H_ */