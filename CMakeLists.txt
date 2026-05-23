cmake_minimum_required(VERSION 3.22)
project(NetScope VERSION 2.0.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2)

add_library(netscope_lib src/parser.cpp src/analyzer.cpp)
target_include_directories(netscope_lib PUBLIC include)

add_executable(netscope_server src/server.cpp)
target_link_libraries(netscope_server netscope_lib)

enable_testing()
add_executable(test_parser  tests/test_parser.cpp)
target_link_libraries(test_parser  netscope_lib)
add_test(NAME ParserTests COMMAND test_parser)

add_executable(test_analyzer tests/test_analyzer.cpp)
target_link_libraries(test_analyzer netscope_lib)
add_test(NAME AnalyzerTests COMMAND test_analyzer)
