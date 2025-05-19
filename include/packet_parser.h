#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <stdlib.h>

#define ETH_ALEN 6
#define INET_ADDRSTRLEN 16

// 自定义以太网头部结构
typedef struct {
    uint8_t dest_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint16_t ether_type;
} MyEthHeader;

// 自定义IP头部结构
typedef struct {
    uint8_t version_ihl;     // 版本和头部长度
    uint8_t tos;             // 服务类型
    uint16_t total_length;   // 总长度
    uint16_t id;             // 标识
    uint16_t flags_offset;   // 标志和片偏移
    uint8_t ttl;             // 生存时间
    uint8_t protocol;        // 协议
    uint16_t checksum;       // 头部校验和
    uint32_t src_ip;         // 源IP地址
    uint32_t dst_ip;         // 目的IP地址
} MyIpHeader;

// 数据包信息结构
typedef struct {
    const uint8_t *data;
    size_t length;
} PacketInfo;

// 函数声明
PacketInfo* create_packet_info(const uint8_t *data, size_t length);
void free_packet_info(PacketInfo *info);
void parse_packet(PacketInfo *info);

#endif // PACKET_PARSER_H
    