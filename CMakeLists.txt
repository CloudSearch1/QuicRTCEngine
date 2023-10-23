#设置Windows sdk版本
set(CMAKE_SYSTEM_VERSION 10.0 CACHE STRING "Windows SDK version" FORCE)

# 设置CMake的最低版本要求
cmake_minimum_required(VERSION 3.0)

# 设置项目名称
project(Xquic)

# 添加子目录
add_subdirectory(src)

