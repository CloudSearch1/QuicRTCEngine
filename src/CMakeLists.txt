project(Xquic)

if (MSVC)
    set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
    )
    foreach(CompilerFlag ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()
endif(MSVC)


# 设置构建类型，默认为 Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# 设置输出路径
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

#扫描当前目录下的.cpp和.h文件
file(GLOB_RECURSE MAIN_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

# 添加可执行文件
add_executable(Xquic ${MAIN_SOURCE_FILES} )

# 设置依赖头文件路径
set(MULTP_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/Dependencies/multp/platform/multp/h)
set(XQUIC_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/Dependencies/libquic/include/xquic)
set(LIBEVENT_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/Dependencies/libevent/include)

# 包含头文件路径
target_include_directories(Xquic PRIVATE ${MULTP_INCLUDE_DIR})
target_include_directories(Xquic PRIVATE ${XQUIC_INCLUDE_DIR})
target_include_directories(Xquic PRIVATE ${LIBEVENT_INCLUDE_DIR})

# 设置库文件路径
set(MULTP_LIB_DIR ${CMAKE_SOURCE_DIR}/Dependencies/multp/build/win/Win32/Debug)
set(XQUIC_DEBUG_LIB_DIR ${CMAKE_SOURCE_DIR}/Dependencies/libquic/libs/Debug/Win32)
set(LIBEVENT_DEBUG_LIB_DIR ${CMAKE_SOURCE_DIR}/Dependencies/libevent/build/lib/Debug)


# 添加附加库目录
target_link_directories(Xquic PRIVATE ${MULTP_LIB_DIR})
target_link_directories(Xquic PRIVATE ${XQUIC_DEBUG_LIB_DIR})
target_link_directories(Xquic PRIVATE ${LIBEVENT_DEBUG_LIB_DIR})

# 链接所需的库
target_link_libraries(Xquic PRIVATE
	multp.lib
	libquic.lib
	event.lib
	event_core.lib
	event_extra.lib
	Ws2_32.lib
)

# 添加application文件夹
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Xquic-test)
# 添加utils文件夹
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/utils)
# 添加log文件夹
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/log)

# 设置输出路径
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

# 添加源头文件目录
target_include_directories(Xquic PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/Xquic-test
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/log
)

# 扫描各文件夹中的.cpp和.h文件
file(GLOB_RECURSE APP_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/Xquic-test/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/Xquic-test/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/Xquic-test/*.c")
file(GLOB_RECURSE UTILS_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/utils/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/utils/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/utils/*.c")
file(GLOB_RECURSE LOG_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/log/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/log/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/log/*.c")


# 使用 source_group 命令分组源文件
source_group("Xquic-test" FILES ${APP_SOURCE_FILES})
source_group("Utils" FILES ${UTILS_SOURCE_FILES})
source_group("Log" FILES ${LOG_SOURCE_FILES})


# 设置可执行文件的运行时搜索路径
set_target_properties(Xquic PROPERTIES
    VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
)

# 创建输出路径文件夹
file(MAKE_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
# 复制win32生成的dll到项目输出文件夹
file(COPY "${CMAKE_SOURCE_DIR}/Dependencies/libevent/build/bin/Debug/"
     DESTINATION "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
	 
file(COPY "${CMAKE_SOURCE_DIR}/Dependencies/libquic/libs/Debug/Win32/"
     DESTINATION "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")