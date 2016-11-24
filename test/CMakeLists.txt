add_executable(TestCommitment test-commitment.cpp)
target_link_libraries(TestCommitment COMMIT BITCOMMIT COMMON_TOOLS BYTEARRAYVEC DOT OTX gtest_main gtest)

add_executable(TestDOT test-dot.cpp)
target_link_libraries(TestDOT COMMON_TOOLS BYTEARRAYVEC DOT OTX gtest_main gtest)

add_executable(TestParser test-circuit-parser.cpp)
target_link_libraries(TestParser CIRCUIT gtest_main gtest)

add_executable(TestGarbledCircuit test-garbled-circuit.cpp)
target_link_libraries(TestGarbledCircuit COMMON_TOOLS GARBLING CIRCUIT gtest_main gtest)

add_executable(TestDuploSetup test-duplo-setup.cpp)
target_link_libraries(TestDuploSetup DUPLO COMMON_TOOLS BYTEARRAYVEC STORAGE DOT OTX gtest_main gtest)

add_executable(TestDuploPreprocessAuxData test-duplo-preprocess-aux-data.cpp)
target_link_libraries(TestDuploPreprocessAuxData DUPLO COMMON_TOOLS BYTEARRAYVEC STORAGE DOT OTX gtest_main gtest)

add_executable(TestDuploPreprocessBucketing test-duplo-preprocess-bucketing.cpp)
target_link_libraries(TestDuploPreprocessBucketing DUPLO COMMON_TOOLS BYTEARRAYVEC STORAGE DOT OTX gtest_main gtest)

add_executable(TestDuploEvaluation test-duplo-eval.cpp)
target_link_libraries(TestDuploEvaluation DUPLO COMMON_TOOLS BYTEARRAYVEC STORAGE DOT OTX gtest_main gtest)

add_executable(TestDuploAESCorrectness test-duplo-aes-correctness.cpp)
target_link_libraries(TestDuploAESCorrectness DUPLO COMMON_TOOLS BYTEARRAYVEC STORAGE DOT OTX gtest_main gtest)

add_executable(TestDuploSoldering test-duplo-soldering.cpp)
target_link_libraries(TestDuploSoldering DUPLO COMMON_TOOLS BYTEARRAYVEC STORAGE DOT OTX gtest_main gtest)

add_executable(TestDuploInpBuckets test-duplo-inp-buckets.cpp)
target_link_libraries(TestDuploInpBuckets DUPLO COMMON_TOOLS BYTEARRAYVEC STORAGE DOT OTX gtest_main gtest)

add_executable(TestTimings test-timings.cpp)
target_link_libraries(TestTimings COMMON_TOOLS gtest_main gtest)