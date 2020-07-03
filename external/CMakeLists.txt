find_package(Miniupnpc REQUIRED)

message(STATUS "Using in-tree miniupnpc")
add_subdirectory(miniupnp/miniupnpc)
set_property(TARGET libminiupnpc-static PROPERTY FOLDER "external")
if(MSVC)
  set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -wd4244 -wd4267")
elseif(NOT MSVC)
  set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-undef -Wno-unused-result -Wno-unused-value")
endif()
if(CMAKE_SYSTEM_NAME MATCHES "NetBSD")
	set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -D_NETBSD_SOURCE")
endif()

set(UPNP_LIBRARIES "libminiupnpc-static" PARENT_SCOPE)

if (DO_TESTS)
  add_subdirectory(gtest)
endif()

if(DO_TESTS)
  set_property(TARGET gtest gtest_main PROPERTY FOLDER "external")
endif()
