#ifndef DUPLO_DUPLOEVAL_H_
#define DUPLO_DUPLOEVAL_H_

#include "frigate-duplo/frigate-duplo.h"
#include "dot/alsz-dot-ext-rec.h"
#include "commit/commit-scheme-rec.h"
#include "garbling/eval-garbled-circuit.h"
#include "commit/commit-scheme-rec.h"
#include "commit/bit-commit-scheme-rec.h"

class FrigateDuploEvaluator : public FrigateDuplo {
public:
	FrigateDuploEvaluator(CommonTools& common_tools, uint32_t num_max_parallel_execs = 1);

  void Setup();

  void PreprocessComponentType(std::string component_type, Circuit& circuit, uint32_t num_buckets, uint32_t num_parallel_execs = 1, BucketType bucket_type = SINGLE);

  void PrepareEvaluation(std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t num_parallel_execs = 1);

  std::pair<std::string, uint32_t> SolderGarbledComponents(std::string resulting_component_type, std::vector<std::tuple<std::string, uint32_t, std::vector<uint32_t>>>& input_wire_components, std::vector<std::tuple<std::string, uint32_t, std::vector<uint32_t>>>& output_wire_components, std::vector<std::tuple<std::string, uint32_t, std::vector<uint32_t>>>& resulting_component_out_wires);

  /*
  Performs the required steps for the evaluator to learn all input keys of the garbled component and the actual evaluation of an evaluable component. Notice that this procedure does not produce a plain text output. This allows for more fin-grained output decoding where possibly only a subset of the components output wires are decoded and the remaining ones can be soldered onto a different component, depending on the decoded output part. This effectively allows branching.

  Inputs:
  - std::pair<std::string, uint32_t> components: The component to evaluate.
  - std::vector<std::vector<uint8_t>>& inputs: The plaintext inputs of a party.
  - std::vector<BYTEArrayVector>& output_keys: The destination of the obtained output keys.
  */
  void EvalComponents(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& output_keys, uint32_t num_parallel_execs = 1);

  /*
  Performs the actual output decoding of a previously evaluated component. Notice that it is possible to decode only a subset of the output of the component which allows for future soldering of any remaining non-decoded output keys onto other components.

  Inputs:
  - std::pair<std::string, uint32_t> component_type: The component that has been evaluated.
  - std::vector<uint32_t> output_wires: A vector specifying which output wires that are to be decoded.
  - std::vector<uint8_t> resulting_output: The result vector which will contain the resulting plaintext output.
  */
  void DecodeWires(std::pair<std::string, uint32_t>& component_type, std::vector<uint32_t>& output_wires, std::vector<uint8_t>& resulting_output);

  BYTEArrayVector commit_seed_OTs;
  BYTEArrayVector commit_seed_choices;


private:
  ALSZDOTExtRec ot_rec;

  void CommitReceiveAndCutAndChoose(CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_num_total_garbled, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_circuits_from, uint32_t exec_eval_circuits_to, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data, BYTEArrayVector& eval_hash);

  void BucketAndReceiveEvalCircuits(std::string component_type, CommonTools& exec_common_tools, Circuit& circuit, uint32_t bucket_size, std::vector<uint32_t>& permuted_eval_ids_inv, uint32_t exec_buckets_from, uint32_t exec_num_buckets, std::vector<EvalGarbledCircuit>& aux_garbled_circuits_data, BYTEArrayVector& eval_hash);
  void DebugStoredEvalCircuits(std::string component_type, CommonTools& exec_common_tools, Circuit& circuit, uint32_t exec_buckets_from, uint32_t exec_num_buckets);

  void CommitAuthAndCutAndChoose(CommonTools& exec_common_tools, uint32_t exec_num_auths, uint32_t exec_prg_counter, uint32_t check_factor, bool negate_check_factor, uint32_t exec_eval_auths_from, uint32_t exec_eval_auths_to, std::vector<BYTEArrayVector>& eval_auths, BYTEArrayVector& aux_auth_data, std::vector<uint32_t>& aux_auth_ids, uint8_t aux_auth_delta_data[], std::tuple<std::mutex&, std::condition_variable&, bool&>& delta_signal);

  void BucketAllAuths(std::vector<std::tuple<std::string, Circuit, uint64_t>>& circuit_info, CommonTools& exec_common_tools, uint32_t auth_size, std::vector<uint32_t>& permuted_eval_ids_inv, std::vector<int>& session_circuit_buckets_from, std::vector<int>& session_circuit_buckets_to, std::vector<BYTEArrayVector>& eval_auths, BYTEArrayVector& aux_auth_data, std::vector<uint32_t>& aux_auth_ids, uint8_t aux_auth_delta_data[]);

  void EvalBucketsParallel(std::vector<std::pair<std::string, uint32_t>>& components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& input_keys, std::vector<BYTEArrayVector>& output_keys);

  void EvalBucketsSerial(std::vector<std::pair<std::string, uint32_t>>& components, uint32_t components_from, uint32_t components_to, std::vector<BYTEArrayVector>& input_keys, std::vector<BYTEArrayVector>& output_keys);

  void PreprocessInputs(CommonTools& inp_common_tools, std::vector<std::pair<std::string, uint32_t>>& input_components);

  void DecommitEvalPermBits(CommonTools& inp_common_tools, std::vector<std::pair<std::string, uint32_t>>& input_components);
};

#endif /* DUPLO_DUPLOEVAL_H_ */