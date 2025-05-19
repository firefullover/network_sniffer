#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

#define ETH_ALEN 6
#define INET_ADDRSTRLEN 16

// 以太网头部结构
typedef struct {
    uint8_t dest_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint16_t ether_type;
} MyEthHeader;

// 自定义IP头部结构（使用位域节省空间）
typedef struct __attribute__((packed)) {
    uint8_t version:4;       // 版本
    uint8_t ihl:4;           // 头部长度（以4字节为单位）
    uint8_t tos;             // 服务类型
    uint16_t total_length;   // 总长度（需转换为网络字节序）
    uint16_t id;             // 标识（需转换为网络字节序）
    uint16_t flags_offset;   // 标志+片偏移
    uint8_t ttl;             // 生存时间
    uint8_t protocol;        // 协议
    uint16_t checksum;       // 头部校验和（需转换为网络字节序）
    struct in_addr src_addr; // 源IP地址
    struct in_addr dst_addr; // 目的IP地址
} MyIpHeader;

// 数据包信息结构
typedef struct {
    const uint8_t *data;
    size_t length;
} PacketInfo;

/**
 * @brief 创建一个数据包信息结构体，并复制数据内容。
 * 
 * @param data   指向原始数据包内容的指针
 * @param length 数据包内容的长度（字节数）
 * @return PacketInfo* 指向新分配并初始化的 PacketInfo 结构体指针，需用 free_packet_info 释放
 */
PacketInfo* create_packet_info(const uint8_t *data, size_t length);

/**
 * @brief 释放由 create_packet_info 创建的数据包信息结构体及其内部数据。
 * 
 * @param info 需要释放的 PacketInfo 结构体指针
 */
void free_packet_info(PacketInfo *info);

/**
 * @brief 解析并处理数据包内容（如打印包头信息等）。
 * 
 * @param info 指向待解析的数据包信息结构体
 */
void parse_packet(PacketInfo *info);

#endif // PACKET_PARSER_H