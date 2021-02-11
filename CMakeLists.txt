cmake_minimum_required(VERSION 3.5)

project(mt_shafs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_subdirectory(concurrentqueue)

link_libraries(Threads::Threads ${CMAKE_DL_LIBS} concurrentqueue crypto)

add_executable(mt_shafs main.cpp)
