file(GLOB_RECURSE UTILS_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

target_sources(Xquic PRIVATE ${UTILS_SOURCE_FILES})