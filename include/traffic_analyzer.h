#ifndef TRAFFIC_ANALYZER_H
#define TRAFFIC_ANALYZER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include "packet_logger.h"

// 流量统计结构
typedef struct {
    char local_ip[INET_ADDRSTRLEN];    // 本机IP
    char remote_ip[INET_ADDRSTRLEN];   // 远程IP
    unsigned long outgoing_bytes;       // 流出流量（字节）
    unsigned long incoming_bytes;       // 流入流量（字节）
} TrafficStat;

// 流量统计节点
typedef struct TrafficStatNode {
    TrafficStat stat;
    struct TrafficStatNode *next;
} TrafficStatNode;

// 流量分析器
typedef struct {
    TrafficStatNode *head;  // 头指针
    int count;              // 记录数量
} TrafficAnalyzer;

/**
 * @brief 初始化流量分析器
 * @return TrafficAnalyzer* 返回流量分析器指针
 */
TrafficAnalyzer* init_traffic_analyzer();

/**
 * @brief 从数据包日志管理器分析流量
 * @param analyzer 流量分析器
 * @param logger 数据包日志管理器
 * @return int 成功分析的记录数量
 */
int analyze_traffic(TrafficAnalyzer *analyzer, PacketLogger *logger);

/**
 * @brief 将流量统计结果写入文件
 * @param analyzer 流量分析器
 * @return int 成功写入的记录数量
 */
int write_traffic_stats_to_file(TrafficAnalyzer *analyzer);

/**
 * @brief 释放流量分析器及其所有记录
 * @param analyzer 流量分析器
 */
void free_traffic_analyzer(TrafficAnalyzer *analyzer);

#endif // TRAFFIC_ANALYZER_H