#include "packet_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>

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
    
    // 获取当前时间
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(node->record.timestamp, sizeof(node->record.timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // 填充记录信息
    strncpy(node->record.local_ip, local_ip, INET_ADDRSTRLEN - 1);
    node->record.local_ip[INET_ADDRSTRLEN - 1] = '\0';
    
    strncpy(node->record.remote_ip, remote_ip, INET_ADDRSTRLEN - 1);
    node->record.remote_ip[INET_ADDRSTRLEN - 1] = '\0';
    
    node->record.direction = is_outgoing ? '>' : '<';
    node->record.packet_size = size;
    node->next = NULL;
    
    // 添加到链表
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
    strftime(filename, sizeof(filename), "packet_log_%Y-%m-%d_%H-%M-%S.txt", tm_info);
    
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
    fprintf(file, "# 格式: [时间戳] 本机IP 方向 远程IP 数据包大小(字节)\n\n");
    
    // 写入每条记录
    while (current) {
        fprintf(file, "[%s] %s %c %s %d\n", 
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