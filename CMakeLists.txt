cmake_minimum_required(VERSION 3.10)
project(network_sniffer)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_COMPILER "gcc")

# 查找libpcap库
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap库未找到")
endif()

include_directories(include)

# 主程序源文件
file(GLOB MAIN_SOURCES "src/main.c" "src/packet_logger.c" "src/packet_parser.c" "src/traffic_analyzer.c")

# 测试程序源文件
set(TEST_SOURCES src/test_analyzer.c src/packet_logger.c src/traffic_analyzer.c)

# 主程序
add_executable(traffic_analyzer ${MAIN_SOURCES})
target_link_libraries(traffic_analyzer ${PCAP_LIBRARY} pthread)

# 测试程序
add_executable(test_analyzer ${TEST_SOURCES})
target_link_libraries(test_analyzer pthread)