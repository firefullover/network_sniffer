#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packet_logger.h"
#include "traffic_analyzer.h"

// 从文件中读取数据包记录
int load_packet_logs_from_file(PacketLogger *logger, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("无法打开文件: %s\n", filename);
        return 0;
    }
    
    char line[256];
    int count = 0;
    
    // 跳过文件头部注释行
    while (fgets(line, sizeof(line), file)) {
        if (line[0] != '#' && line[0] != '\n') {
            break;
        }
    }
    
    // 解析每一行数据
    do {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        // 解析行数据: [时间戳] 本机IP 方向 远程IP 数据包大小
        char timestamp[32], local_ip[32], direction[8], remote_ip[32];
        int packet_size;
        
        // 使用sscanf解析行数据
        if (sscanf(line, "[%[^]]] %s %s %s %d", 
                  timestamp, local_ip, direction, remote_ip, &packet_size) == 5) {
            // 确定方向
            int is_outgoing = (strcmp(direction, ">") == 0) ? 1 : 0;
            
            // 记录数据包
            log_packet(logger, local_ip, remote_ip, is_outgoing, packet_size);
            count++;
        }
    } while (fgets(line, sizeof(line), file));
    
    fclose(file);
    printf("从文件 %s 加载了 %d 条数据包记录\n", filename, count);
    return count;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("用法: %s <数据包日志文件>\n", argv[0]);
        return 1;
    }
    
    // 初始化数据包记录器
    PacketLogger *packet_logger = init_packet_logger();
    if (!packet_logger) {
        fprintf(stderr, "初始化数据包记录器失败\n");
        return 1;
    }
    
    // 初始化流量分析器
    TrafficAnalyzer *traffic_analyzer = init_traffic_analyzer();
    if (!traffic_analyzer) {
        fprintf(stderr, "初始化流量分析器失败\n");
        free_packet_logger(packet_logger);
        return 1;
    }
    
    // 从文件加载数据包记录
    load_packet_logs_from_file(packet_logger, argv[1]);
    
    // 分析流量并生成统计报告
    printf("正在分析网络流量...\n");
    int analyzed = analyze_traffic(traffic_analyzer, packet_logger);
    printf("分析了 %d 条数据包记录\n", analyzed);
    
    // 写入流量统计报告
    write_traffic_stats_to_file(traffic_analyzer);
    
    // 释放资源
    free_packet_logger(packet_logger);
    free_traffic_analyzer(traffic_analyzer);
    
    return 0;
}