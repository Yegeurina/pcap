#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include "libnet-macros.h"
#include "libnet-headers.h"
#include "libnet-structures.h"
#include "libnet-asn1.h"
#include "libnet-functions.h"


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

uint16_t printEther(const u_char* packet)
{
    int i;
    struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet;
    printf("[Ethernet]\n");

    printf("SRC MAC : ");
    for(i=0;i<6; i++)
    {
        printf("%02x",eth->ether_shost[i]);
        if(i!=5) printf(":");
    }printf("\n");

    printf("DST MAC : ");
    for(i=0;i<6; i++)
    {
        printf("%02x",eth->ether_dhost[i]);
        if(i!=5) printf(":");
    }printf("\n");

    return eth->ether_type;
}
uint8_t printIPv4(const u_char* packet)
{
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)packet;
    printf("[IP]\n");
    printf("SRC IPv4 : %d\n",ip->ip_src.s_addr);
    printf("DST IPv4 : %d\n",ip->ip_dst.s_addr);
    return ip->ip_p;
}
uint8_t printIPv6(const u_char* packet)
{
    struct libnet_ipv6_hdr* ip = (struct libnet_ipv6_hdr*)packet;
    int i;

    printf("[IP]\n");
     printf("SRC IPv6 : ");
    for(i=0;i<8;i++){
        printf("%d",ip->ip_src.__u6_addr.__u6_addr16[i]);
        if(i!=8) printf(":");
    }printf("\n");

    printf("DST IPv6 : ");
    for(i=0;i<8;i++){
        printf("%d",ip->ip_dst.__u6_addr.__u6_addr16[i]);
        if(i!=8) printf(":");
    }printf("\n");

    return ip->ip_nh;
}
void printTCP(const u_char* packet)
{
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)packet;
    printf("[TCP]\n");
    printf("SRC PORT : %d\n",tcp->th_sport);
    printf("DST PORT : %d\n",tcp->th_dport);
}
/*void printDATA(const u_char* packet)
{
    struct libnet_tcp_hdr* ip = (struct libnet_tcp_hdr*)packet;
    printf("[TCP]\n");
    printf("SRC PORT : ");
    printf("DST PORT : ");
}*/



void packetAnalysis(const u_char* packet)
{
    uint16_t ipType = printEther(packet);
    packet+=LIBNET_ETH_H; // static header size = 14bytes
    uint8_t tcpudp;
    if(ipType==ETHERTYPE_IP) //ipv4
    {
       tcpudp=printIPv4(packet);
       packet+=LIBNET_IPV4_H; //static header size = 20bytes
    }
    else if(ipType == 0x86DD) //ipv6
    {
        tcpudp=printIPv6(packet);
        packet+=LIBNET_IPV6_H;
    }
    else
    {
        printf("This packet cannot be analyzed.\n ");
        exit(1);
    }

    printTCP(packet);
    packet+=LIBNET_TCP_H;

//    printUDP(packet);
//    packet+=LIBNET_UDP_H;

//    printDATA(packet);
}


void packet_lookup()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
       exit(1);
    }

    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printf("%u bytes captured\n", header->caplen);

        packetAnalysis(packet);

    }

    pcap_close(pcap);

}

int main(int argc, char* argv[])
{

    if (!parse(&param, argc, argv))
        return -1;

    packet_lookup();

}
