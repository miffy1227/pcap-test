#include <stdio.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN]; // Destination Ethernet address
    uint8_t  ether_shost[ETHER_ADDR_LEN]; // Source Ethernet address
    uint16_t ether_type;                 // Protocol (in network byte order)
};

void print_mac(uint8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_ip(uint32_t ip) {
    for (int i = 0; i < 4; i++) {
        printf("%u", (ip >> (i * 8)) & 0xFF);
        if (i < 3) printf(".");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while (1) {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        printf("%u bytes captured\n", header->caplen);

        
        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
        if (ntohs(eth_hdr->ether_type) != 0x0800)
            continue;

        printf("Destination MAC: ");
        print_mac(eth_hdr->ether_dhost);
        printf(", Source MAC: ");
        print_mac(eth_hdr->ether_shost);
        printf("\n");

        // IP
        const uint8_t *ip_packet = packet + sizeof(struct libnet_ethernet_hdr);
        struct ip *ip_hdr = (struct ip *)ip_packet;
        if (ip_hdr->ip_p != IPPROTO_TCP)
            continue;

        printf("Source IP: ");
        print_ip(ip_hdr->ip_src.s_addr);
        printf(", Destination IP: ");
        print_ip(ip_hdr->ip_dst.s_addr);
        printf("\n");

        // TCP 
        const uint8_t *tcp_packet = ip_packet + (ip_hdr->ip_hl * 4);
        struct tcphdr *tcp_hdr = (struct tcphdr *)tcp_packet;

        printf("Source Port: %u, Destination Port: %u\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));

        //data  
        const uint8_t *tcp_data = tcp_packet + (tcp_hdr->doff * 4);
	printf("TCP Data: ");
	int data_len = header->caplen - (tcp_data - packet);
	if (data_len > 0) {
    		for (int i = 0; i < 10 && i < data_len; i++) {
        		printf("%02x ", tcp_data[i]);
    		}
	} else {
    		printf("-");
	}
	printf("\n");
    }

    pcap_close(handle);
    return 0;
}

