include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

set(dispatcher_SRCS
  DictDispatcher.cc
  TreeMapDispatcher.cc
  UniversalDispatcher.cc
  UnorderedMapDispatcher.cc
  VectorDispatcher.cc
)

bro_add_subdir_library(llanalyzer_dispatcher ${dispatcher_SRCS})
