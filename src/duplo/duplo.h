#ifndef DUPLO_DUPLO_H_
#define DUPLO_DUPLO_H_

#include "garbling/garbling-handler.h"
#include "circuit/circuit.h"
#include "util/typedefs.h"
#include "util/byte-array-vec.h"
#include "util/common-tools.h"
#include "util/storage.h"
extern "C" {
#include "util/sha1.h"
}

/*
A superclass to the two subclasses DuploConstructor and DuploEvaluator.
*/

enum BucketType {
  SINGLE = 0,
  MAJORITY = 1
};

enum OutType {
  CONST_OUT = 0,
  EVAL_OUT = 1,
  ALL_OUT = 2
};

class Duplo {

public:
  Duplo(CommonTools& common_tools, uint32_t num_max_parallel_execs = 1);

  /*
  Starts by clearing any previously saved persistent state on the filesystem. Calling Setup() therefore signals a completely fresh session and previously produced garblings, baseOTs, commitment seedOTs, etc are wiped clean.
  Next the baseOTs and a small OT extension step is done to produce the required seedOTs for the string and bit-commitment system.
  Does not take input as the security parameters are fixed to CSEC=128 and SSEC=40. Should only be called once in the lifetime of the current session.
  */
  virtual void Setup() = 0;

  /*
  Performs the garbling, committing, cut-and-choose and bucketing of circuits and stores this to disk for future use. For sake of efficiency use as few calls as possible for any one component type (preferably one call per circuit type).

  Inputs:
  - std::string component_type: A string identifier, typically name of the component/circuit such as "AES-128", "ADD_64", "SHA-256". The naming is important and must be identical for consecutive PreprocessComponentType calls of the same circuit (which by the way is discouraged for sake of efficiency).
  - Circuit circuit: The circuit that will be garbled.
  - uint32_t num_circuits: The number of garbled version to produce and store to disk for future use.
  */
  virtual void PreprocessComponentType(std::string component_type, Circuit& circuit, uint32_t num_circuits, uint32_t num_parallel_execs = 1, BucketType bucket_type = SINGLE) = 0;

  /*
  Performs the soldering of wire authenticators to all previously constructed components (can be from many calls to PreprocessComponentType) since last PrepareEvaluation() call. It is very important that this is called at the end of a Preprocess cycle as the garbled components are not complete until the wire authenticators have been attached. We separate the creation of wire authenticators from the PreprocessComponentType for sake of efficiency as the cut-and-choose works much better for larger number of items, in this case wire authenticators for all garbled components in this "cycle".

  Takes no input as the code keeps internal state about how many authenticators need to be produced. Calling PrepareEvaluation() signals an end to a preprocessing cycle and should be minimized to as few calls as possible to maximize efficiency.
  */
  virtual void PrepareComponents(std::vector<std::pair<std::string, uint32_t>>& input_components, uint32_t num_parallel_execs = 1) = 0;

  virtual void SolderGarbledComponents(std::string& res_component, ComposedCircuit& composed_circuit, uint32_t num_parallel_execs = 1) = 0;

    /*
  Performs the required steps for the evaluator to learn all input keys of the garbled component and the actual evaluation of an evaluable component. Notice that this procedure does not produce a plain text output. This allows for more fin-grained output decoding where possibly only a subset of the components output wires are decoded and the remaining ones can be soldered onto a different component, depending on the decoded output part. This effectively allows branching.

  Inputs:
  - std::pair<std::string, uint32_t> components: The component to evaluate.
  - std::vector<std::vector<uint8_t>>& inputs: The plaintext inputs of a party.
  - std::vector<BYTEArrayVector>& output_keys: The destination of the obtained output keys.
  */
  virtual void EvalComponents(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& output_keys, uint32_t num_parallel_execs = 1, bool exchange_output_keys = true) = 0;

  virtual void EvalComposedComponents(std::string& res_component, std::vector<std::vector<uint8_t>>& inputs, std::vector<BYTEArrayVector>& const_output_keys, uint32_t num_parallel_execs = 1) = 0;

  virtual void DecodeKeys(std::vector<std::pair<std::string, uint32_t>>& components, std::vector<BYTEArrayVector>& output_keys, std::vector<std::vector<uint8_t>>& outputs, uint32_t num_parallel_execs = 1) = 0;

  CommonTools& common_tools;
  std::vector<std::unique_ptr<CommonTools>> common_tools_vec;
  ctpl::thread_pool thread_pool;
  Storage persistent_storage;
  std::vector<std::tuple<std::string, Circuit, uint64_t>> circuit_info;
  std::unordered_map<std::string, Circuit> string_to_circuit_map;
  std::unordered_map<std::string, ComposedCircuit> string_to_composed_circuit_map;

  Circuit inp_bucket_circuit;

  uint64_t curr_num_ready_inputs;
  uint64_t inputs_used;
  uint64_t curr_prg_counter;

  void WeightedRandomString(uint8_t res[], int weight, int res_length, PRNG& rnd, bool negate_probability);

  void FindBestSingleParams(uint32_t num_buckets, uint32_t& res_bucket, long double& check_val, bool& check_val_negate);
  void MaxSingleProb(int b, uint32_t num_buckets, mpf_class& curr_p, mpf_class& max_prob);

  void FindBestMajorityParams(uint32_t num_buckets, uint32_t& res_bucket, long double& check_val, bool& check_val_negate, uint32_t catch_reciproc_prob);
  void MaxProbMajority(int b, uint32_t num_buckets, mpf_class& curr_p, mpf_class& max_prob, uint32_t catch_reciproc_prob);
  
  void ComputeCheckFraction(int check_frac, int num_items, float& slack_frac, float& final_rep_frac, bool negate_check_probability);

  void ComputeIndices(uint32_t num_circuits, Circuit& circuit, uint32_t& num_inp_keys, uint32_t& num_out_keys, uint32_t& num_deltas, uint32_t& num_commit_keys, uint32_t& num_base_keys, uint32_t& input_keys_idx, uint32_t& output_keys_idx, uint32_t& deltas_idx);

  uint32_t GetNumInpWires(ComposedCircuit& composed_circuit);
  uint32_t GetNumOutWires(ComposedCircuit& composed_circuit, OutType out_type);
  uint32_t GetNumTotalOutWires(ComposedCircuit& composed_circuit);

  void GenExecTools(uint32_t num_parallel_execs);
};

#endif /* DUPLO_DUPLO_H_ */