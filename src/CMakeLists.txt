set(NETWORK_SRCS util/network.cpp)
add_library(NETWORK ${NETWORK_SRCS})

set(BYTEARRAYVEC_SRCS util/byte-array-vec.cpp)
add_library(BYTEARRAYVEC ${BYTEARRAYVEC_SRCS})

set(STORAGE_SRCS util/storage.cpp)
add_library(STORAGE ${STORAGE_SRCS})

set(CHANNEL_SRCS util/channel.cpp)
add_library(CHANNEL ${CHANNEL_SRCS})
target_link_libraries(CHANNEL ${ZMQ_LIBRARIES})

set(BCH_SRCS commit/bch.c)
add_library(BCH ${BCH_SRCS})

set(PRG_SRCS prg/random.cpp prg/aes-ni.cpp)
add_library(PRG ${PRG_SRCS})

set(CIRCUIT_SRCS circuit/circuit-parser.cpp)
add_library(CIRCUIT ${CIRCUIT_SRCS})

set(DOT_SRCS dot/alsz-dot-ext-rec.cpp dot/alsz-dot-ext-snd.cpp dot/alsz-dot-ext.cpp)
add_library(DOT ${DOT_SRCS})
target_link_libraries(DOT NETWORK OTX)

set(COMMIT_SRCS commit/commit-scheme-rec.cpp commit/commit-scheme-snd.cpp commit/commit-scheme.cpp commit/ecc.cpp)
add_library(COMMIT ${COMMIT_SRCS})
target_link_libraries(COMMIT BCH PRG)

set(BITCOMMIT_SRCS commit/bit-commit-scheme-rec.cpp commit/bit-commit-scheme-snd.cpp commit/bit-commit-scheme.cpp)
add_library(BITCOMMIT ${BITCOMMIT_SRCS})
target_link_libraries(BITCOMMIT PRG)

set(GARBLING_SRCS garbling/garbling-handler.cpp garbling/garbled-circuit.cpp garbling/const-garbled-circuit.cpp garbling/eval-garbled-circuit.cpp)
add_library(GARBLING ${GARBLING_SRCS})
target_link_libraries(GARBLING BYTEARRAYVEC)

set(COMMON_TOOLS_SRCS util/common-tools.cpp)
add_library(COMMON_TOOLS ${COMMON_TOOLS_SRCS})
target_link_libraries(COMMON_TOOLS NETWORK OTX_CRYPTO PRG CHANNEL)

set(DUPLO_SRCS duplo/duplo-evaluator.cpp duplo/duplo-constructor.cpp duplo/duplo.cpp)
add_library(DUPLO ${DUPLO_SRCS})
target_link_libraries(DUPLO STORAGE COMMIT BITCOMMIT GARBLING CIRCUIT DOT COMMON_TOOLS)

add_executable(DuploConstructor mains/duplo-const-main.cpp)
target_link_libraries(DuploConstructor DUPLO)

add_executable(DuploEvaluator mains/duplo-eval-main.cpp)
target_link_libraries(DuploEvaluator DUPLO)

add_executable(MPCOutsourcingConstructor mains/mpc-outsourcing-const.cpp)
target_link_libraries(MPCOutsourcingConstructor DUPLO)

add_executable(MPCOutsourcingEvaluator mains/mpc-outsourcing-eval.cpp)
target_link_libraries(MPCOutsourcingEvaluator DUPLO)
