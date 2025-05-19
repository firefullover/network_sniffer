#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <sys/types.h>
#include "packet_parser.h" 

volatile int running = 1;
pcap_t *handle = NULL;

// 信号处理函数
void handle_signal(int signal) {
    running = 0;
    pcap_breakloop(handle);
}

// 数据包解析线程
void *packet_parsing_callback(void *arg) {
    PacketInfo *packet_info = (PacketInfo *)arg;
    parse_packet(packet_info);       // 解析数据包
    free_packet_info(packet_info);   // 释放数据包内存
    return NULL;
}

// 抓包回调函数
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    int *packet_count = (int *)user;
    (*packet_count)++;
    
    // 申请内存保存数据包，并由线程来处理
    PacketInfo *packet_info = create_packet_info(bytes, h->caplen);
    if (!packet_info) return;
    
    pthread_t tid;
    pthread_create(&tid, NULL, packet_parsing_callback, packet_info);
    pthread_detach(tid);
}

int main() {
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
    int packet_count = 0;
    pcap_loop(handle, 0, packet_handler, (u_char *)&packet_count);

    // 关闭抓包并释放资源
    pcap_close(handle);
    pcap_freealldevs(devs);
    printf("捕获到 %d 个数据包\n", packet_count);
    printf("抓包结束\n");

    return 0;
}