#include "packet_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

PacketInfo* create_packet_info(const uint8_t *data, size_t length) {
    PacketInfo *info = (PacketInfo*)malloc(sizeof(PacketInfo));
    if (!info) return NULL;
    
    // 分配内存并复制数据包内容
    uint8_t *data_copy = (uint8_t*)malloc(length);
    if (!data_copy) {
        free(info);
        return NULL;
    }
    
    memcpy(data_copy, data, length);
    info->data = data_copy;
    info->length = length;
    return info;
}

void free_packet_info(PacketInfo *info) {
    if (info) {
        if (info->data) free((void*)info->data); // 释放数据内容
        free(info); // 释放结构体本身
    }
}

void parse_packet(PacketInfo *info) {
    // 检查数据包有效性
    if (!info || !info->data || info->length < sizeof(MyEthHeader)) {
        printf("无效的数据包\n");
        return;
    }
    
    // 解析以太网头部
    const MyEthHeader *eth_header = (const MyEthHeader*)info->data;
    
    // 检查是否为IP数据包（以太网类型为0x0800）
    uint16_t ether_type = ntohs(eth_header->ether_type);
    if (ether_type != 0x0800) {
        printf("非IP数据包，无法解析IP地址\n");
        return;
    }
    
    // 检查数据包长度是否足够包含IP头部
    if (info->length < sizeof(MyEthHeader) + sizeof(MyIpHeader)) {
        printf("IP数据包长度不足\n");
        return;
    }
    
    // 解析IP头部
    const MyIpHeader *ip_header = (const MyIpHeader*)(info->data + sizeof(MyEthHeader));
    
    // 提取源IP和目的IP地址
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->src_addr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->dst_addr), dst_ip, INET_ADDRSTRLEN);
    
    // 计算IP层总长度
    int total_size = ntohs(ip_header->total_length);
    
    // 输出解析结果
    printf("源IP地址: %s,目的IP地址: %s,流量大小: %d bytes\n", src_ip, dst_ip, total_size);
}