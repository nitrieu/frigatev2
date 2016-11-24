#include "test.h"

#include "duplo/duplo-constructor.h"
#include "duplo/duplo-evaluator.h"

#include "util/storage.h"

static uint32_t num_max_parallel_execs = 2;

class TestDuplo : public ::testing::Test {

protected:
  zmq::context_t context_const;
  zmq::context_t context_eval;

  CommonTools common_tools_const;
  CommonTools common_tools_eval;

  DuploConstructor duplo_const;
  DuploEvaluator duplo_eval;

  uint32_t num_execs_components = 1;
  uint32_t num_execs_auths = 1;
  uint32_t num_execs_online = 1;

  TestDuplo() :
    context_const(zmq::context_t(1)),
    context_eval(zmq::context_t(1)),
    common_tools_const(constant_seeds[0], "localhost", default_port, 0, context_const, GLOBAL_PARAMS_CHAN),
    common_tools_eval(constant_seeds[1], "localhost", default_port, 1, context_eval, GLOBAL_PARAMS_CHAN),
    duplo_const(common_tools_const, num_max_parallel_execs),
    duplo_eval(common_tools_eval, num_max_parallel_execs) {
  };
};