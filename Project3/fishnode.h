#ifndef FISHNODE_H
#define FISHNODE_H

#include "fish.h"
 
typedef struct {
   fn_l2addr_t dst;
   fn_l2addr_t src;
   uint16_t cksum;
   uint16_t len;
} __attribute__((packed)) l2_header_t;

typedef struct  {
   uint8_t ttl;
   uint8_t  proto;
   uint32_t packet_id;
   fnaddr_t src;
   fnaddr_t dst;
} __attribute__((packed)) l3_header_t;

typedef struct {
   uint32_t query;
   fnaddr_t l3addr;
   fn_l2addr_t l2addr;
} __attribute__((packed)) arp_t;


typedef struct {
   fnaddr_t src;
   uint32_t pkt_id;
} src_pkt_pair;

typedef struct src_pkt {
   src_pkt_pair src ;
   struct src_pkt *next;
} src_pkt;

src_pkt *head = NULL;

typedef struct fwd_table_t {
   fnaddr_t dst;
   int prefix_length;
   fnaddr_t next_hop;
   int metric;
   char type;
   void *data;
   struct fwd_table_t *next;
} fwd_table_t;

fwd_table_t *fwd_table_head = NULL;
#endif
