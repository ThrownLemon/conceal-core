cmake_minimum_required(VERSION 3.10)
project(ccx_pqc_spike CXX)
set(CMAKE_CXX_STANDARD 11)
set(RUST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust)
set(RUST_LIB ${RUST_DIR}/target/release/libccx_pqc.a)
# Build the Rust PQ crypto static lib via cargo, then link it into the C++ target.
add_custom_command(OUTPUT ${RUST_LIB}
  COMMAND cargo build --release
  WORKING_DIRECTORY ${RUST_DIR}
  COMMENT "cargo build (Rust PQ crypto)" VERBATIM)
add_custom_target(rust_pqc DEPENDS ${RUST_LIB})
add_executable(pqc_test cpp/main.cpp)
target_include_directories(pqc_test PRIVATE cpp)
add_dependencies(pqc_test rust_pqc)
target_link_libraries(pqc_test ${RUST_LIB} pthread dl m)
