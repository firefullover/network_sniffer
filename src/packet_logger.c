#include "packet_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <netinet/in.h>

// 初始化数据包日志管理器
PacketLogger* init_packet_logger() {
    PacketLogger *logger = (PacketLogger*)malloc(sizeof(PacketLogger));
    if (!logger) return NULL;

    logger->head = NULL;
    logger->tail = NULL;
    logger->count = 0;
    pthread_mutex_init(&logger->mutex, NULL);

    return logger;
}

// 添加一条数据包记录
void log_packet(PacketLogger *logger, const char *local_ip, const char *remote_ip, int is_outgoing, int size) {
    if (!logger || !local_ip || !remote_ip) return;

    // 创建新节点
    PacketLogNode *node = (PacketLogNode*)malloc(sizeof(PacketLogNode));
    if (!node) return;

    // 记录时间
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(node->record.timestamp, sizeof(node->record.timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // 填充记录信息
    strncpy(node->record.local_ip, local_ip, INET_ADDRSTRLEN - 1);
    node->record.local_ip[INET_ADDRSTRLEN - 1] = '\0';

    strncpy(node->record.remote_ip, remote_ip, INET_ADDRSTRLEN - 1);
    node->record.remote_ip[INET_ADDRSTRLEN - 1] = '\0';

    strncpy(node->record.direction, is_outgoing ? "->" : "<-", sizeof(node->record.direction) - 1);
    node->record.direction[sizeof(node->record.direction) - 1] = '\0';

    node->record.packet_size = size;
    node->next = NULL;

    // 记录数据（链表结构）
    pthread_mutex_lock(&logger->mutex);

    if (logger->tail) {
        logger->tail->next = node;
        logger->tail = node;
    } else {
        logger->head = logger->tail = node;
    }

    logger->count++;
    pthread_mutex_unlock(&logger->mutex);
}

// 将所有记录写入文件
int write_logs_to_file(PacketLogger *logger) {
    if (!logger) return 0;

    // 生成文件名
    char filename[100];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(filename, sizeof(filename), "packet_log.txt", tm_info);

    // 打开文件
    FILE *file = fopen(filename, "w");
    if (!file) return 0;

    int count = 0;
    PacketLogNode *current;

    // 锁定互斥锁并遍历链表
    pthread_mutex_lock(&logger->mutex);
    current = logger->head;

    // 写入文件头
    fprintf(file, "# 网络数据包记录 - 生成时间: %s\n", ctime(&now));
    // fprintf(file, "# 格式: [时间戳] 本机IP 传输方向 远程IP 数据包大小(字节)\n");

    // 写入每条记录
    while (current) {
        fprintf(file, "[%s] %s %s %s %d字节\n",
                current->record.timestamp,
                current->record.local_ip,
                current->record.direction,
                current->record.remote_ip,
                current->record.packet_size);

        current = current->next;
        count++;
    }

    pthread_mutex_unlock(&logger->mutex);

    // 关闭文件
    fclose(file);
    printf("已将 %d 条数据包记录写入文件: %s\n", count, filename);

    return count;
}

// 释放日志管理器及其所有记录
void free_packet_logger(PacketLogger *logger) {
    if (!logger) return;

    // 锁定互斥锁
    pthread_mutex_lock(&logger->mutex);

    // 释放所有节点
    PacketLogNode *current = logger->head;
    PacketLogNode *next;

    while (current) {
        next = current->next;
        free(current);
        current = next;
    }

    // 解锁并销毁互斥锁
    pthread_mutex_unlock(&logger->mutex);
    pthread_mutex_destroy(&logger->mutex);

    // 释放管理器
    free(logger);
}

// 获取本机IP地址
int get_local_ip(char *local_ip, size_t size) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;

    if (getifaddrs(&ifaddr) == -1) {
        return 0;
    }

    // 遍历所有网络接口
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        family = ifa->ifa_addr->sa_family;

        // 只处理IPv4地址
        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                    local_ip, size, NULL, 0, NI_NUMERICHOST);
            if (s != 0) continue;

            // 跳过回环接口
            if (strcmp(local_ip, "127.0.0.1") == 0) continue;

            // 找到一个有效的非回环IPv4地址
            freeifaddrs(ifaddr);
            return 1;
        }
    }

    freeifaddrs(ifaddr);
    return 0;
}

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

// 打印流量统计
int write_traffic_stats_to_file(TrafficAnalyzer *analyzer) {
    if (!analyzer) return 0;

    // 生成文件名
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char filepath[50];
    strftime(filepath, sizeof(filepath), "%Y-%m-%dT%H:%M.txt", tm_info);

    // 打开文件
    FILE *file = fopen(filepath, "w");
    if (!file) return 0;

    // 写入文件头
    fprintf(file, "# 流量统计报告 - 生成时间: %s\n", ctime(&now));

    // 打印表格头部
    fprintf(file, "+-------------------+------------------+-----------------+------------------+------------------+\n");
    fprintf(file, "|      本机IP        |      远程IP      |      流出流量    |      流入流量    |        总流量     |\n");
    fprintf(file, "+-------------------+------------------+-----------------+------------------+------------------+\n");

    int count = 0;
    TrafficStatNode *current = analyzer->head;
    unsigned long total_outgoing = 0;
    unsigned long total_incoming = 0;

    // 获取当前时间戳
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // 写入每条统计记录（新格式）
    while (current) {
        fprintf(file, "| %-17s | %-16s | %'12lu字节 | %'12lu字节 | %'12lu字节 |\n",
                current->stat.local_ip,
                current->stat.remote_ip,
                current->stat.outgoing_bytes,
                current->stat.incoming_bytes,
                current->stat.outgoing_bytes + current->stat.incoming_bytes);

        fprintf(file, "+-------------------+------------------+------------------+-----------------+------------------+\n");

        total_outgoing += current->stat.outgoing_bytes;
        total_incoming += current->stat.incoming_bytes;
        current = current->next;
        count++;
    }


    // 写入总计
    fprintf(file, "\n# 统计总流量\n");
    fprintf(file, "# 流出: %lu 字节\n", total_outgoing);
    fprintf(file, "# 流入: %lu 字节\n", total_incoming);
    fprintf(file, "# 总计: %lu 字节\n", total_outgoing + total_incoming);

    // 关闭文件
    fclose(file);
    // printf("一共记录了 %d 个ip与本机进行数据交换\n", count);
    printf("\n流量统计报告已生成: %s\n",filepath);

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

// 初始化数据包日志管理器和流量分析器
int init_packet_logger_and_analyzer(PacketLogger **logger, TrafficAnalyzer **analyzer) {
    if (!logger || !analyzer) return -1;

    *logger = init_packet_logger();
    if (!*logger) {
        fprintf(stderr, "初始化数据包日志管理器失败\n");
        return -1;
    }

    *analyzer = init_traffic_analyzer();
    if (!*analyzer) {
        fprintf(stderr, "初始化流量分析器失败\n");
        free_packet_logger(*logger);
        *logger = NULL;
        return -1;
    }

    return 0;
}

// 生成日志并释放资源
void generate_logs_and_free(PacketLogger *logger, TrafficAnalyzer *analyzer) {
    if (!logger || !analyzer) return;

    // 生成数据包日志:记录了本次程序运行时抓到的所有ip包的大小
    // write_logs_to_file(logger);

    // 生成流量统计日志
    analyze_traffic(analyzer, logger);
    write_traffic_stats_to_file(analyzer);

    // 释放资源
    free_packet_logger(logger);
    free_traffic_analyzer(analyzer);
}