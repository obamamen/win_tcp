cmake_minimum_required(VERSION 4.0)
project(win_tcp)

set(CMAKE_CXX_STANDARD 17)

add_executable(win_tcp main.cpp)
target_link_libraries(win_tcp PRIVATE ws2_32)
