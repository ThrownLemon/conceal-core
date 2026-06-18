add_definitions(-DMINIUPNP_STATICLIB)
include_directories(${CMAKE_SOURCE_DIR}/external/parallel_hashmap)

file(GLOB_RECURSE BlockchainExplorer BlockchainExplorer/*)
file(GLOB_RECURSE Common Common/*)
file(GLOB_RECURSE crypto crypto/*)
file(GLOB_RECURSE CryptoNoteCore CryptoNoteCore/* CryptoNoteConfig.h)
file(GLOB_RECURSE CryptoNoteProtocol CryptoNoteProtocol/*)
file(GLOB_RECURSE Daemon Daemon/*)
file(GLOB_RECURSE Http HTTP/*)
file(GLOB_RECURSE InProcessNode InProcessNode/*)
file(GLOB_RECURSE Logging Logging/*)
file(GLOB_RECURSE Optimizer Optimizer/*)
file(GLOB_RECURSE Mnemonics Mnemonics/*)
file(GLOB_RECURSE NodeRpcProxy NodeRpcProxy/*)
file(GLOB_RECURSE P2p P2p/*)
file(GLOB_RECURSE Rpc Rpc/*)
file(GLOB_RECURSE Serialization Serialization/*)
file(GLOB_RECURSE ConcealWallet ConcealWallet/*)
file(GLOB_RECURSE Transfers Transfers/*)
file(GLOB_RECURSE Wallet Wallet/*)
file(GLOB_RECURSE WalletLegacy WalletLegacy/*)
file(GLOB_RECURSE JsonRpcServer JsonRpcServer/*)
file(GLOB_RECURSE PaymentGate PaymentGate/*)
file(GLOB_RECURSE PaymentGateService PaymentGateService/*)

if(MSVC OR MINGW)
  file(GLOB_RECURSE System System/* Platform/Windows/System/*)
elseif(APPLE)
  file(GLOB_RECURSE System System/* Platform/OSX/System/*)
else()
  file(GLOB_RECURSE System System/* Platform/Linux/System/*)
endif()

source_group("" FILES $${Common} ${crypto} ${CryptoNoteCore} ${CryptoNoteProtocol} ${Daemon} ${JsonRpcServer} ${Http} ${Logging} ${NodeRpcProxy} ${P2p} ${Rpc} ${Serialization} ${ConcealWallet} ${System} ${Transfers} ${Wallet} ${WalletLegacy})

add_library(BlockchainExplorer STATIC ${BlockchainExplorer})
add_library(Common STATIC ${Common})
add_library(crypto STATIC ${crypto})
add_library(CryptoNoteCore STATIC ${CryptoNoteCore})
add_library(Http STATIC ${Http})
add_library(InProcessNode STATIC ${InProcessNode})
add_library(Logging STATIC ${Logging})
add_library(Mnemonics STATIC ${Mnemonics})
add_library(NodeRpcProxy STATIC ${NodeRpcProxy})
add_library(Rpc STATIC ${Rpc})
add_library(P2P STATIC ${CryptoNoteProtocol} ${P2p})
add_library(Serialization STATIC ${Serialization})
add_library(System STATIC ${System})
add_library(Transfers STATIC ${Transfers})
add_library(Wallet STATIC ${Wallet} ${WalletLegacy})
add_library(PaymentGate STATIC ${PaymentGate})
add_library(JsonRpcServer STATIC ${JsonRpcServer})

add_executable(Daemon ${Daemon})
add_executable(ConcealWallet ${ConcealWallet})
add_executable(PaymentGateService ${PaymentGateService})
add_executable(Optimizer ${Optimizer})

if (MSVC)
  target_link_libraries(System ws2_32)
endif ()

if (MINGW)
  target_link_libraries(Common dnsapi)
  target_link_libraries(P2P bcrypt)
  target_link_libraries(System ws2_32)
endif ()

# CryptoNoteCore now references the ccx-pqc FFI (PQ ring-sig verification in Blockchain.cpp),
# so it needs the header at compile time and every executable that links CryptoNoteCore must
# also link libccx_pqc.a (+ its system deps). The .a must follow CryptoNoteCore on each link line.
add_dependencies(CryptoNoteCore ccx_pqc)
target_include_directories(CryptoNoteCore PRIVATE ${CCX_PQC_INCLUDE})

# WalletLegacy now references the hardcoded testnet ML-KEM key header (PQ message PoC, Option B),
# so the Wallet lib needs the ccx-pqc include dir at compile time.
add_dependencies(Wallet ccx_pqc)
target_include_directories(Wallet PRIVATE ${CCX_PQC_INCLUDE})

# TransfersConsumer scans PQ messages (tx-extra 0x06) on testnet with the hardcoded testnet ML-KEM
# secret header (PQ message PoC, Option B), so the Transfers lib also needs the ccx-pqc include dir.
add_dependencies(Transfers ccx_pqc)
target_include_directories(Transfers PRIVATE ${CCX_PQC_INCLUDE})

# PqSpendClient (Rpc lib) builds + relays a PQ spend via the shared CryptoNoteCore builder and the
# hardcoded testnet ML-KEM secret header, so the Rpc lib also needs the ccx-pqc include dir.
add_dependencies(Rpc ccx_pqc)
target_include_directories(Rpc PRIVATE ${CCX_PQC_INCLUDE})

target_link_libraries(Daemon CryptoNoteCore P2P Rpc System Http Logging Common crypto libminiupnpc-static BlockchainExplorer ${Boost_LIBRARIES} Serialization)
add_dependencies(Daemon ccx_pqc)
target_include_directories(Daemon PRIVATE ${CCX_PQC_INCLUDE})
target_link_libraries(Daemon ${CCX_PQC_LIB} pthread dl m)
target_link_libraries(ConcealWallet Wallet NodeRpcProxy Transfers Rpc Http CryptoNoteCore System Logging Common crypto ${Boost_LIBRARIES} Serialization Mnemonics)
target_link_libraries(ConcealWallet ${CCX_PQC_LIB} pthread dl m)
target_link_libraries(PaymentGateService PaymentGate JsonRpcServer Wallet NodeRpcProxy Transfers CryptoNoteCore crypto P2P Rpc Http System Logging Common InProcessNode libminiupnpc-static BlockchainExplorer ${Boost_LIBRARIES} Serialization)
target_link_libraries(PaymentGateService ${CCX_PQC_LIB} pthread dl m)
target_link_libraries(Optimizer PaymentGate Rpc Http CryptoNoteCore Logging Serialization crypto System Common ${Boost_LIBRARIES})
target_link_libraries(Optimizer ${CCX_PQC_LIB} pthread dl m)

# PQ injector — testnet PoC tool (CIP-0001): builds+signs a v3 PQ tx, prints raw hex.
add_executable(PqInjector ${CMAKE_SOURCE_DIR}/pqc/tools/pq_injector.cpp)
add_dependencies(PqInjector ccx_pqc)
target_include_directories(PqInjector PRIVATE ${CCX_PQC_INCLUDE})
target_link_libraries(PqInjector CryptoNoteCore Serialization System Logging Common crypto ${Boost_LIBRARIES})
target_link_libraries(PqInjector ${CCX_PQC_LIB} pthread dl m)
set_property(TARGET PqInjector PROPERTY OUTPUT_NAME "pq_injector")

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux" OR APPLE AND NOT ANDROID)
  target_link_libraries(ConcealWallet -lresolv)
  target_link_libraries(Daemon -lresolv)
  target_link_libraries(PaymentGateService -lresolv)
endif ()

add_dependencies(Rpc version)
add_dependencies(Daemon version)
add_dependencies(ConcealWallet version)
add_dependencies(PaymentGateService version)
add_dependencies(P2P version)

set_property(TARGET ConcealWallet PROPERTY OUTPUT_NAME "concealwallet")
set_property(TARGET PaymentGateService PROPERTY OUTPUT_NAME "walletd")
set_property(TARGET Daemon PROPERTY OUTPUT_NAME "conceald")
set_property(TARGET Optimizer PROPERTY OUTPUT_NAME "optimizer")