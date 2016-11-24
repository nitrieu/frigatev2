#ifndef DUPLO_DUPLO_H_
#define DUPLO_DUPLO_H_

#include "duplo/duplo.h"
#include "garbling/garbling-handler.h"
#include "circuit/circuit.h"
#include "util/typedefs.h"
#include "util/byte-array-vec.h"
#include "util/common-tools.h"
#include "util/storage.h"

/*
A superclass to the two subclasses FrigateDuploConstructor and FrigateDuploEvaluator.
*/
enum BucketType {
	SINGLE   = 0,
	MAJORITY = 1
};

class FrigateDuplo {

public:
	FrigateDuplo(CommonTools& common_tools, uint32_t num_max_parallel_execs = 1);

  
  virtual void PreprocessComponentTypeForCircuits(std::string component_type, std::vector<Circuit>& circuits, uint32_t num_circuits, uint32_t num_parallel_execs = 1, BucketType bucket_type = SINGLE) = 0;


	//std::vector<std::vector<std::tuple<std::string, Circuit, uint64_t>>> circuits_info;
	//std::vector<std::unordered_map<std::string, Circuit>> strings_to_circuits_map;
 // std::unordered_map<std::tuple<std::string, uint32_t>, uint64_t> perm_bits_pos_map;


};

#endif /* DUPLO_DUPLO_H_ */