#ifndef PACKET_LOGGER_H
#define PACKET_LOGGER_H

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

// 数据包日志管理器
typedef struct {
    PacketLogNode *head;     // 头指针
    PacketLogNode *tail;     // 尾指针
    pthread_mutex_t mutex;
    int count; // 记录数量
} PacketLogger;

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

#endif // PACKET_LOGGER_H