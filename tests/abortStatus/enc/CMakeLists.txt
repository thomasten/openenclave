# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../abortStatus.edl enclave gen)

add_enclave(TARGET abortStatus_enc UUID c55a7e2a-b857-4518-98df-4d294d0ab14d CXX SOURCES enc.cpp ${gen})

target_compile_features(abortStatus_enc PRIVATE cxx_generalized_initializers)

target_include_directories(abortStatus_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})
