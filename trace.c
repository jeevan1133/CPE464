#include "smartalloc.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "checksum.h"

#define RET 255
#define ARGCOUNT 3
#define PARTMAX 6
#define DEFAULT 5
#define ETHER_SIZE 14
#define ARP "ARP"
#define IPV4 "IP"
#define UNKNOWN "Unknown"
#define ERROR(_A, _B)\
{\
printf("Error opening file: %s Error: %s\n", (_A),(_B));\
exit(RET);\
}

typedef struct {
   uint packet_num;
   uint packet_len;
   uint8_t partNum;
} packet_info;

/* IP Header */
typedef struct  {
   uint8_t ver_ihl;
#define IP_V(ip)   (((ip)->ver_ihl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ver_ihl & 0x0f)
   uint8_t  tos;
   uint16_t total_length;
   uint16_t id;
   uint16_t flags_fo; // 3 bits flags and 13 bits fragment-offset
   uint8_t  ttl;
   uint8_t  protocol;
   uint16_t checksum;
   struct   in_addr ip_src, ip_dst;
   u_int   op_pad;
} ip_header_t;

typedef   __uint32_t tcp_seq;
typedef __uint32_t tcp_cc;

/* UDP Header */
typedef struct udp_header{
   u_short sport;          // Source port
   u_short dport;          // Destination port
   u_short len;            // Datagram length
   u_short crc;            // Checksum
}  udp_header;

/* ICMP Header */
typedef struct {
   uint8_t type;
   uint8_t code;
   uint16_t checksum;
   uint32_t data;
}  icmp_header_t;

typedef struct {
   u_short th_sport;   /* source port */
   u_short th_dport;   /* destination port */
   tcp_seq th_seq;    /* sequence number */
   tcp_seq th_ack;    /* acknowledgement number */
   u_char th_offx2;   /* data offset, rsvd */
#define TH_OFF(th)   (((th)->th_offx2 & 0xf0) >> 4)
   u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
   u_short th_win;    /* window */
   u_short th_sum;    /* checksum */
   u_short th_urp;    /* urgent pointer */
}  tcphdr;

typedef struct {
   struct in_addr src_ip;
   struct in_addr dst_ip;
   uint8_t zeroes;
   uint8_t protocol;
   uint16_t len;
} pseudo_header;

void processICMP(const u_char *packet, const uint8_t ip_len, uint8_t partNum) {

   if (partNum < 4) {
      printf("\n\tUnknown PDU\n");
      return;
   }
   icmp_header_t  *icmp = (icmp_header_t *)(packet + ip_len);
   printf("\n\tICMP Header\n");
   printf("\t\tType: %s\n", (icmp->type) == 0 ? "Reply" :
         (icmp->type == 8) ? "Request" : UNKNOWN) ;
}

void print_protocol_type(uint8_t protocol) {
   printf("\t\tProtocol: ");
   if (protocol == 1)
      printf("ICMP\n");
   else if (protocol == 2)
      printf("TCP\n");
   else if (protocol == 3)
      printf("UDP\n");
   else
      printf("Unknown\n");
}

void common_ports(uint16_t port) {
   if (port == 80) {
      printf("HTTP\n");
   }
   else if (port == 20 || port == 21){
      printf("FTP\n");
   }
   else if (port == 25) {
      printf("SMTP\n");
   }
   else if (port == 23) {
      printf("Telnet\n");
   }
   else if (port == 110){
      printf("POP3\n");
   }
   else {
      printf("%d\n", port);
   }
}

void print_ports(uint16_t sport, uint16_t dport) {
   printf("\t\tSource Port:  ");
   common_ports(sport);
   printf("\t\tDest Port:  ");
   common_ports( dport);
}

void processTCP(u_char *ip, uint8_t len, uint8_t partNum)
{

   if (partNum < 4) {
      printf("\n\tUnknown PDU\n");
      return;
   }

   /*Process ip and parse TCP header */
   tcphdr *tcp = (tcphdr *)(ip + len);
   pseudo_header pseudo;
   ip_header_t * pIph = (ip_header_t*) ip;

   printf("\n\tTCP Header\n");
   print_ports(ntohs(tcp->th_sport), ntohs(tcp->th_dport));
   printf("\t\tSequence Number: %lu\n", (long unsigned int)ntohl(tcp->th_seq));
   printf("\t\tACK Number: %lu\n", (long unsigned int)ntohl(tcp->th_ack));
   printf("\t\tSYN Flag: %s\n" ,
               ((tcp->th_flags & TH_SYN) == TH_SYN) ? "Yes" : "No");
   printf("\t\tRST Flag: %s\n" ,
                ((tcp->th_flags & TH_RST) == TH_RST) ? "Yes" : "No");
   printf("\t\tFIN Flag: %s\n" ,
               ((tcp->th_flags & TH_FIN) == TH_FIN) ? "Yes" : "No");
   printf("\t\tWindow Size: %d\n", ntohs(tcp->th_win));
   
   pseudo.src_ip = pIph->ip_src ;
   pseudo.dst_ip = pIph->ip_dst;
   pseudo.protocol = 6;
   pseudo.zeroes = 0;
   u_short total_len = (ntohs(pIph->total_length) - len);
   pseudo.len = htons(total_len);

   uint16_t cksum = in_cksum((u_short*)&pseudo, (unsigned)sizeof(pseudo));
   cksum += in_cksum((u_short*)tcp, total_len);
   cksum = ~cksum;

   printf("\t\tChecksum: %s (0x%x)\n", (cksum == 0 ) ? "Correct" : "Incorrect",
                        ntohs(tcp->th_sum));
}

void processUDP( u_char* ip, uint8_t len, uint8_t partNum)
{
   if (partNum < DEFAULT) {
      printf("\n\tUnknown PDU\n");
      return;
   }

   udp_header *udp = (udp_header *)(ip +len);
   printf("\n\tUDP Header\n");
   print_ports(ntohs(udp->sport), ntohs(udp->dport));
}

void printIPV4(const u_char *packet,
               const struct pcap_pkthdr *pkthdr,
               const uint8_t partNum) {
   /* Prints IPV4 packet*/
   if (partNum <= 2) {
      printf("\n\n\tUnknown PDU\n");
      return;
   }
   ip_header_t *ip = (ip_header_t *) (packet + ETHER_SIZE);
   u_int length = pkthdr->len;
   length -= sizeof(struct ether_header);
   printf("\n\n\tIP Header\n");

   if (length < (sizeof *ip))
   {
      printf("\n\n\tUnknown PDU\n");
      return;
   }

   uint8_t len = IP_HL(ip);
   len *= 4;

   printf("\t\tTOS: 0x%hx\n", (short)ip->tos);
   printf("\t\tTTL: %d\n", ip->ttl);

   uint8_t protocol = (ip->protocol == 1) ? 1 :
               (ip->protocol == 6)  ? 2 : (ip->protocol == 17) ? 3 :  4 ;
   print_protocol_type(protocol);

   u_short chksum = in_cksum((unsigned short*) ip, len);
   printf("\t\tChecksum: %s (0x%x)\n", ((chksum == 0) ? "Correct" : "Incorrect"),
         ntohs(ip->checksum));

   printf("\t\tSender IP: %s\n", inet_ntoa(ip->ip_src));
   printf("\t\tDest IP: %s\n", inet_ntoa(ip->ip_dst));
   
   if(protocol == 1) {
      processICMP((u_char*)ip, len, partNum);
   }
   else if (protocol == 2) {
      processTCP((u_char*)ip, len, partNum);
   }
   else if (protocol == 3) {
      processUDP((u_char*)ip, len, partNum);
   }
}

void printARP(const u_char *packet, const uint8_t partNum) {
   /* if partNum is less than 2 print unknown PDU */
   if (partNum < 2) {
      printf("\n\n\tUnknown PDU\n");
      return;
   }

   char sourceIP[INET_ADDRSTRLEN];
   char destIP[INET_ADDRSTRLEN];
   struct ether_arp *arp_header;
   arp_header = (struct ether_arp *)(packet + sizeof (struct ether_header));
   inet_ntop(AF_INET, &(arp_header->arp_spa), sourceIP, INET_ADDRSTRLEN);
   inet_ntop(AF_INET, &(arp_header->arp_tpa), destIP, INET_ADDRSTRLEN);

   printf("\n\n\tARP Header\n");
   printf("\t\tOpcode: %s\n",
         ((((arp_header->ea_hdr.ar_op)/256) % 2) == 0 ) ? "Reply" : "Request");
   printf("\t\tSender MAC: %s\n",
         ether_ntoa((struct ether_addr*) arp_header->arp_sha));
   printf("\t\tSender IP: %s\n", sourceIP);
   printf("\t\tTarget MAC: %s\n",
         ether_ntoa((struct ether_addr*) arp_header->arp_tha));
   printf("\t\tTarget IP: %s\n", destIP);
}

void check_type(struct ether_header *ether,
                const u_char *packet,
                const uint8_t partNum,
                const struct pcap_pkthdr *pkthdr
                )
{
   if (ntohs(ether->ether_type) == ETHERTYPE_IP) {
     printf("%s", IPV4);
     printIPV4(packet, pkthdr, partNum);
   }
   else if (ntohs(ether->ether_type) == ETHERTYPE_ARP) {
      printf("%s", ARP);
      printARP(packet, partNum);
   }
   else {
      printf("%s", UNKNOWN);
   }
}


void usage(char *exfile, int partNum)
{
   printf("Usage: %s trace.file <PartNum>\n", exfile);
   printf("where PartNum = 1 (ethernet only), 2 (plus ARP), 3 (plus IP),");
   printf(" 4 (plus TCP), 5 plus ICMP and UDP)\n");
   if (partNum) {
      printf("your PartNum is: %d\n", partNum);
   }
   exit(RET);
}

void print_headers(const u_char *packet, uint8_t partNum,
                  const struct pcap_pkthdr *packet_header)

{
   struct ether_header *ether = (struct ether_header *) packet;
   printf("\n\tEthernet Header\n");
   printf("\t\tDest MAC: %s\n",
              ether_ntoa((const struct ether_addr*)ether->ether_dhost));
   printf("\t\tSource MAC: %s\n",
              ether_ntoa((const struct ether_addr*)ether->ether_shost));
   printf("\t\tType: ");
   check_type(ether, packet, partNum, packet_header);
}

void checkArgs(int argc, char **argv, packet_info *p_info)
{
   if (argc == 1)
      usage(argv[0], 0);
   if (argc >= 3) {
      if (atoi(argv[2]) >=  PARTMAX) {
         usage(argv[0], atoi(argv[2]));
      }
      p_info->partNum = (uint8_t)(atoi(argv[2]));
   }
}

void packet_handler(u_char *args,
                    const struct pcap_pkthdr *packet_header,
                    const u_char *packet
                    )
{
   packet_info *pack_info = (packet_info *) args;
   pack_info->packet_num++;
   pack_info->packet_len = packet_header->len;
   printf("\nPacket number: %d  Packet Len: %d\n",
         pack_info->packet_num, pack_info->packet_len);
   print_headers(packet, pack_info->partNum, packet_header);
}

int main(int argc, char *argv[])
{
   char error_buffer[PCAP_ERRBUF_SIZE];
   pcap_t *handle;
   packet_info *pack_info = malloc(sizeof (packet_info));
   /* check arguments */
   pack_info->partNum = DEFAULT;
   checkArgs(argc, argv, pack_info);
   pack_info->packet_num = 0;


   /* Open the file to read the packets */
   if ((handle = pcap_open_offline(argv[1], error_buffer)) == NULL) {
      free(pack_info);
      ERROR(argv[1], error_buffer);
   }
   /* The file is open for sniffing. 
    */
   if ((pcap_loop(handle, 0, packet_handler, (u_char*) pack_info)) == -1)
   {
      pcap_close(handle);
      ERROR(argv[1], error_buffer);
      exit(RET);
   }
   free(pack_info);
   pcap_close(handle);
   return 0;
}
