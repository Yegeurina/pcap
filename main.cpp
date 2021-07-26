#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "libnet.h"

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
    return ntohs(eth->ether_type);
}

void PrintIPv4adr(uint32_t IPadr)
{
    int i;
    uint8_t adr[4];
    adr[3]=(IPadr>>24)&0xFF;
    adr[2]=(IPadr>>16)&0xFF;
    adr[1]=(IPadr>>8)&0xFF;
    adr[0]=IPadr&0xFF;
    for(i=0;i<4;i++)
    {
        printf("%d",adr[i]);
        if(i!=3) printf(".");
    }
    printf("\n");
}

uint8_t printIPv4(const u_char* packet)
{
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)packet;
    printf("[IPv4]\n");
    printf("SRC IPv4 : ");
    PrintIPv4adr(ip->ip_src.s_addr);
    printf("DST IPv4 : ");
    PrintIPv4adr(ip->ip_dst.s_addr);
    return ip->ip_p;
}


void printTCP(const u_char* packet)
{
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)packet;
    printf("[TCP]\n");
    printf("SRC PORT : %d\n",ntohs(tcp->th_sport));
    printf("DST PORT : %d\n",ntohs(tcp->th_dport));
}

void printUDP(const u_char* packet)
{
    struct libnet_udp_hdr* udp = (struct libnet_udp_hdr*)packet;
    printf("[UDP]\n");
    printf("SRC PORT : %d\n",ntohs(udp->uh_sport));
    printf("DST PORT : %d\n",ntohs(udp->uh_dport));
}

void printDATA(const u_char* packet)
{
    int i;
    printf("[DATA]\n");
    for(i=0;i<8;i++)
        printf("%02x ",packet[i]);
    printf("\n");
}




void packetAnalysis(const u_char* packet)
{
    uint16_t ipType = printEther(packet);
    packet+=LIBNET_ETH_H; // stLIBNET_UDP_Hatic header size = 14bytes
    uint8_t checkTCPUDP;

    if(ipType==ETHERTYPE_IP) //ipv4
    {
       checkTCPUDP=printIPv4(packet);
       packet+=LIBNET_IPV4_H; //static header size = 20bytes
    }
    else
    {
        printf("This packet cannot be analyzed.\n ");
        exit(1);
    }


    if(checkTCPUDP==0x06)
    {
        printTCP(packet);
        packet+=LIBNET_TCP_H;
    }
    else if(checkTCPUDP==0x11)
    {
        printUDP(packet);
        packet+=LIBNET_UDP_H;
    }
    else
    {
        printf("This packet cannot be analyzed.\n ");
        exit(1);
    }

    if(packet==NULL)
        printf("NO DATA");
    else
        printDATA(packet);
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

        printf("===================\n");

        printf("%u bytes captured\n", header->caplen);

        packetAnalysis(packet);

        printf("===================\n\n");

    }

    pcap_close(pcap);

}

int main(int argc, char* argv[])
{

    if (!parse(&param, argc, argv))
        return -1;

    packet_lookup();

}
