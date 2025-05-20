#include "traffic_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// 初始化流量分析器
TrafficAnalyzer* init_traffic_analyzer() {
    TrafficAnalyzer *analyzer = (TrafficAnalyzer*)malloc(sizeof(TrafficAnalyzer));
    if (!analyzer) return NULL;
    
    analyzer->head = NULL;
    analyzer->count = 0;
    
    return analyzer;
}

// 查找或创建流量统计节点
static TrafficStatNode* find_or_create_stat_node(TrafficAnalyzer *analyzer, const char *local_ip, const char *remote_ip) {
    // 先查找是否已存在该IP对的统计节点
    TrafficStatNode *current = analyzer->head;
    while (current) {
        if (strcmp(current->stat.local_ip, local_ip) == 0 && 
            strcmp(current->stat.remote_ip, remote_ip) == 0) {
            return current; // 找到匹配的节点
        }
        current = current->next;
    }
    
    // 未找到，创建新节点
    TrafficStatNode *node = (TrafficStatNode*)malloc(sizeof(TrafficStatNode));
    if (!node) return NULL;
    
    // 初始化节点数据
    strncpy(node->stat.local_ip, local_ip, INET_ADDRSTRLEN - 1);
    node->stat.local_ip[INET_ADDRSTRLEN - 1] = '\0';
    
    strncpy(node->stat.remote_ip, remote_ip, INET_ADDRSTRLEN - 1);
    node->stat.remote_ip[INET_ADDRSTRLEN - 1] = '\0';
    
    node->stat.outgoing_bytes = 0;
    node->stat.incoming_bytes = 0;
    
    // 添加到链表头部
    node->next = analyzer->head;
    analyzer->head = node;
    analyzer->count++;
    
    return node;
}

// 从数据包日志管理器分析流量
int analyze_traffic(TrafficAnalyzer *analyzer, PacketLogger *logger) {
    if (!analyzer || !logger) return 0;
    
    int count = 0;
    PacketLogNode *current;
    
    // 锁定互斥锁并遍历链表
    pthread_mutex_lock(&logger->mutex);
    current = logger->head;
    
    // 处理每条记录
    while (current) {
        // 查找或创建统计节点
        TrafficStatNode *stat_node = find_or_create_stat_node(
            analyzer, 
            current->record.local_ip, 
            current->record.remote_ip
        );
        
        if (stat_node) {
            // 根据方向累加流量
            if (strcmp(current->record.direction, "->") == 0) {
                // 流出流量
                stat_node->stat.outgoing_bytes += current->record.packet_size;
            } else if (strcmp(current->record.direction, "<-") == 0) {
                // 流入流量
                stat_node->stat.incoming_bytes += current->record.packet_size;
            }
            count++;
        }
        
        current = current->next;
    }
    
    pthread_mutex_unlock(&logger->mutex);
    return count;
}

// 将流量统计结果写入文件
int write_traffic_stats_to_file(TrafficAnalyzer *analyzer) {
    if (!analyzer) return 0;
    
    // 生成文件名
    char filename[100];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char filepath[150];
    strftime(filepath, sizeof(filepath), "../traffic_stats_%Y-%m-%d_%H-%M-%S.txt", tm_info);
    
    // 打开文件
    FILE *file = fopen(filepath, "w");
    if (!file) return 0;
    
    // 写入文件头
    fprintf(file, "# 网络流量统计报告 - 生成时间: %s", ctime(&now));
    fprintf(file, "# 格式: [本机IP] <-> [远程IP] | 流出: xxx字节 | 流入: xxx字节 | 总计: xxx字节\n\n");
    
    // 打印表格头部
    fprintf(file, "+-----------------+----------------+---------------+---------------+----------------+\n");
    fprintf(file, "|     本机IP      |     远程IP     |   流出流量    |   流入流量    |    总流量     |\n");
    fprintf(file, "+-----------------+----------------+---------------+---------------+----------------+\n");
    
    int count = 0;
    TrafficStatNode *current = analyzer->head;
    unsigned long total_outgoing = 0;
    unsigned long total_incoming = 0;
    
    // 获取当前时间戳
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // 写入每条统计记录（新格式）
    while (current) {
        fprintf(file, "| %-15s | %-14s | %10lu字节 | %10lu字节 | %11lu字节 |\n",
                current->stat.local_ip,
                current->stat.remote_ip,
                current->stat.outgoing_bytes,
                current->stat.incoming_bytes,
                current->stat.outgoing_bytes + current->stat.incoming_bytes);
        
        fprintf(file, "+-----------------+----------------+---------------+---------------+----------------+\n");
        
        total_outgoing += current->stat.outgoing_bytes;
        total_incoming += current->stat.incoming_bytes;
        current = current->next;
        count++;
    }
    
    // 写入总计
    // 打印表格尾部
    fprintf(file, "| %-15s | %-14s | %10lu字节 | %10lu字节 | %11lu字节 |\n",
            "总计", "", total_outgoing, total_incoming, total_outgoing + total_incoming);
    fprintf(file, "+-----------------+----------------+---------------+---------------+----------------+\n");
    
    // 写入时间信息
    fprintf(file, "\n# 报告生成时间: %s\n", timestamp);
    
    // 关闭文件
    fclose(file);
    printf("已将 %d 条流量统计记录写入文件: %s\n", count, filename);
    
    return count;
}

// 释放流量分析器及其所有记录
void free_traffic_analyzer(TrafficAnalyzer *analyzer) {
    if (!analyzer) return;
    
    // 释放所有节点
    TrafficStatNode *current = analyzer->head;
    TrafficStatNode *next;
    
    while (current) {
        next = current->next;
        free(current);
        current = next;
    }
    
    // 释放分析器
    free(analyzer);
}