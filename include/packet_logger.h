#ifndef COMBINED_TRAFFIC_LOGGER_H
#define COMBINED_TRAFFIC_LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>

// 数据包记录结构
typedef struct {
    char timestamp[20];              // 时间戳 [YYYY-MM-DD hh:mm:ss]
    char local_ip[INET_ADDRSTRLEN];  // 本机IP
    char direction[3];               // 方向: '->' 发送, '<-' 接收
    char remote_ip[INET_ADDRSTRLEN]; // 远程IP
    int packet_size;                 // 数据包大小(字节)
} PacketRecord;

// 数据包记录链表节点
typedef struct PacketLogNode {
    PacketRecord record;
    struct PacketLogNode *next;
} PacketLogNode;

// 数据包管理器
typedef struct {
    PacketLogNode *head;     // 头指针
    PacketLogNode *tail;     // 尾指针
    pthread_mutex_t mutex;
    int count; // 记录数量
} PacketLogger;

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
 * @brief 初始化数据包日志管理器
 * @return PacketLogger* 返回数据包日志管理器指针
 */
PacketLogger* init_packet_logger();

/**
 * @brief 添加一条数据包记录
 * @param logger 日志管理器
 * @param local_ip 本机IP
 * @param remote_ip 远程IP
 * @param is_outgoing 是否为发出的数据包(0:接收, 1:发送)
 * @param size 数据包大小(字节)
 */
void log_packet(PacketLogger *logger, const char *local_ip, const char *remote_ip, int is_outgoing, int size);

/**
 * @brief 将所有记录写入文件
 * @param logger 日志管理器
 * @return int 成功写入的记录数量
 */
int write_logs_to_file(PacketLogger *logger);

/**
 * @brief 释放日志管理器及其所有记录
 * @param logger 日志管理器
 */
void free_packet_logger(PacketLogger *logger);

/**
 * @brief 获取本机IP地址
 * @param local_ip 存储本机IP的缓冲区
 * @param size 缓冲区大小
 * @return int 成功返回1，失败返回0
 */
int get_local_ip(char *local_ip, size_t size);

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

/**
 * @brief 生成日志并释放资源
 * @param logger 数据包日志管理器
 * @param analyzer 流量分析器
 * @return int 成功返回1，失败返回0
 */
int init_packet_logger_and_analyzer(PacketLogger **logger, TrafficAnalyzer **analyzer);

/**
 * @brief 生成日志并释放资源
 * @param logger 数据包日志管理器
 * @param analyzer 流量分析器
 */
void generate_logs_and_free(PacketLogger *logger, TrafficAnalyzer *analyzer);

#endif // COMBINED_TRAFFIC_LOGGER_H