#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <pcap.h>
#include "packet_parser.h" 
#include "packet_logger.h"
#include "traffic_analyzer.h"

volatile int running = 1;                 // 运行标志
pcap_t *handle = NULL;                    // 抓包句柄
PacketLogger *packet_logger = NULL;       // 数据包记录器
char local_ip[INET_ADDRSTRLEN] = {0};     // 设备IP

// 信号处理函数
void handle_signal(int signal) {
    running = 0;
    pcap_breakloop(handle);
}

// 数据包解析线程
void *packet_parsing_callback(void *arg) {
    PacketInfo *packet_info = (PacketInfo *)arg;
    parse_packet(packet_info);  // 解析数据包
    
    // 检查数据包有效性
    if (!packet_info || !packet_info->data || packet_info->length < sizeof(MyEthHeader) ) {
        free_packet_info(packet_info);   // 释放数据包内存
        return NULL;
    }
    
    // 解析以太网头部
    const MyEthHeader *eth_header = (const MyEthHeader*)packet_info->data;
    
    // 检查是否为IP数据包（以太网类型为0x0800）
    uint16_t ether_type = ntohs(eth_header->ether_type);
    if (ether_type == 0x0800 && packet_info->length >= sizeof(MyEthHeader) + sizeof(MyIpHeader)) {
        // 解析IP头部
        const MyIpHeader *ip_header = (const MyIpHeader*)(packet_info->data + sizeof(MyEthHeader));
        
        // 提取源IP和目的IP地址
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->src_addr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->dst_addr), dst_ip, INET_ADDRSTRLEN);
        
        // 计算IP层总长度
        int total_size = ntohs(ip_header->total_length);
        
        // 判断数据包方向（发送或接收）
        int is_outgoing = 0;
        if (strcmp(src_ip, local_ip) == 0) {
            is_outgoing = 1;  // 本机发出的数据包
            log_packet(packet_logger, local_ip, dst_ip, is_outgoing, total_size);
        } else if (strcmp(dst_ip, local_ip) == 0) {
            is_outgoing = 0;  // 本机接收的数据包
            log_packet(packet_logger, local_ip, src_ip, is_outgoing, total_size);
        }
    }
    
    free_packet_info(packet_info);   // 释放数据包内存
    return NULL;
}

// 抓包回调函数
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // 申请内存保存数据包，并传递给线程来处理
    PacketInfo *packet_info = create_packet_info(bytes, h->caplen, h->ts);
    if (!packet_info) return;
    
    pthread_t tid;
    pthread_create(&tid, NULL, packet_parsing_callback, packet_info);
    pthread_detach(tid);
}

int main() {
    // 初始化数据包记录器
    packet_logger = init_packet_logger();
    if (!packet_logger) {
        fprintf(stderr, "初始化数据包记录器失败\n");
        return 1;
    }
    
    // 初始化流量分析器
    TrafficAnalyzer *traffic_analyzer  = init_traffic_analyzer();
    if (!traffic_analyzer) {
        fprintf(stderr, "初始化流量分析器失败\n");
        free_packet_logger(packet_logger);
        return 1;
    }
    
    // 获取本机IP地址
    if (!get_local_ip(local_ip, INET_ADDRSTRLEN)) {
        return 1;
    }
    printf("本机IP地址: %s\n", local_ip);
    
    // 设置信号处理器
    signal(SIGINT, handle_signal);

    char errbuf[PCAP_ERRBUF_SIZE];      // 错误缓冲区
    pcap_if_t *devs;                    // 网卡设备列表

    // 获取所有网卡设备
    if (pcap_findalldevs(&devs, errbuf) == -1) {
        fprintf(stderr, "无法获取网卡设备列表: %s\n", errbuf);
        return 1;
    }
    if (devs == NULL) {
        fprintf(stderr, "没有找到网卡设备\n");
        return 1;
    }

    // 打开网卡设备
    handle = pcap_open_live(devs->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("无法打开网卡设备: %s\n", errbuf);
        pcap_freealldevs(devs);
        return 0;
    }

    // 开始抓包
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // 按下ctrl+c触发信号，停止抓包，并记录包的数据流量
    write_logs_to_file(packet_logger);
    
    // 统计流量并生成日志
    analyze_traffic(traffic_analyzer, packet_logger);
    write_traffic_stats_to_file(traffic_analyzer);

    // 释放资源
    pcap_close(handle);
    pcap_freealldevs(devs);

    free_packet_logger(packet_logger);// 释放数据包记录器
    free_traffic_analyzer(traffic_analyzer);// 释放流量统计器

    return 0;
}