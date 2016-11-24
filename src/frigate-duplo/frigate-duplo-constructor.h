#ifndef DUPLO_DUPLOCONST_H_
#define DUPLO_DUPLOCONST_H_

#include "frigate-duplo/frigate-duplo.h"
#include "duplo/duplo.h"
#include "duplo/duplo-constructor.h"
#include "dot/alsz-dot-ext-snd.h"
#include "garbling/const-garbled-circuit.h"
#include "commit/bit-commit-scheme-snd.h"
#include "commit/commit-scheme-snd.h"

class FrigateDuploConstructor : public FrigateDuplo, public Duplo {
public:
	FrigateDuploConstructor(CommonTools& common_tools, uint32_t num_max_parallel_execs = 1);

  void Setup();

	void PreprocessComponentTypeForCircuits(std::string component_type, std::vector<Circuit>& circuits, uint32_t num_circuits, uint32_t num_parallel_execs = 1, BucketType bucket_type = SINGLE);

  void PreprocessComponentType(std::string component_type, Circuit& circuit, uint32_t num_buckets, uint32_t num_parallel_execs = 1, BucketType bucket_type = SINGLE);

  void PrepareEvaluation(std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t num_parallel_execs = 1);

  std::pair<std::string, uint32_t> SolderGarbledComponents(std::string resulting_component_type, std::vector<std::tuple<std::string, uint32_t, std::vector<uint32_t>>>& input_wire_components, std::vector<std::tuple<std::string, uint32_t, std::vector<uint32_t>>>& output_wire_components, std::vector<std::tuple<std::string, uint32_t, std::vector<uint32_t>>>& resulting_component_out_wires);

  /*
  Performs the required steps for the evaluator to learn all input keys of the garbled component. The component must be evaluable for DeliverInput to be successful.

  Inputs:
  - std::vector<std::pair<std::string, uint32_t>>& components: The components that is to be made evaluable.
  - std::vector<std::vector<uint8_t>>& input: The plaintext inputs of a party.
  */
  void EvalComponents(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<std::vector<uint8_t>>& inputs, uint32_t num_parallel_execs = 1);

  /*
  Performs the actual output decoding of a previously evaluated component. Notice that it is possible to decode only a subset of the output of the component which allows for future soldering of any remaining non-decoded output keys onto other components.

  Inputs:
  - std::pair<std::string, uint32_t> component_type: The component that has been evaluated.
  - std::vector<uint32_t> output_wires: A vector specifying which output wires that are to be decoded.
  */
  void DecodeWires(std::pair<std::string, uint32_t>& component_type, std::vector<uint32_t>& output_wires);

  BYTEArrayVector commit_seed_OTs0;
  BYTEArrayVector commit_seed_OTs1;

private:
  ALSZDOTExtSnd ot_snd;

  void CommitGarbleAndCutAndChoose(CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_num_total_garbled, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_circuits_from, uint32_t exec_eval_circuits_to, std::vector<ConstGarbledCircuit>& aux_garbled_circuits_data);

  void BucketAndSendEvalCircuits(std::string component_type, CommonTools& exec_common_tools, Circuit& circuit, uint32_t bucket_size, std::vector<uint32_t>& permuted_eval_ids_inv, uint32_t exec_buckets_from, uint32_t exec_num_buckets, std::vector<ConstGarbledCircuit>& aux_garbled_circuits_data);
  void DebugStoredEvalCircuits(std::string component_type, CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_buckets_from, uint32_t exec_num_buckets);

  void CommitAuthAndCutAndChoose(CommonTools& exec_common_tools, uint32_t exec_num_auths, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_auths_from, uint32_t exec_eval_auths_to, std::vector<BYTEArrayVector>& aux_auth_data, BYTEArrayVector& aux_auth_delta_data, std::tuple<std::mutex&, std::condition_variable&, bool&>& delta_signal);

  void BucketAllAuths(std::vector<std::tuple<std::string, Circuit, uint64_t>>& circuit_info, CommonTools& exec_common_tools, uint32_t auth_size, std::vector<uint32_t>& permuted_eval_ids_inv, std::vector<int>& session_circuit_buckets_from, std::vector<int>& session_circuit_buckets_to, std::vector<BYTEArrayVector>& aux_auth_data, BYTEArrayVector& aux_auth_delta_data);

  void PreprocessInputs(CommonTools& inp_common_tools, std::vector<std::pair<std::string, uint32_t>>& input_components);

  void DecommitEvalPermBits(CommonTools& in_common_tools, std::vector<std::pair<std::string, uint32_t>>& input_components);

};

#endif /* DUPLO_DUPLOCONST_H_ */