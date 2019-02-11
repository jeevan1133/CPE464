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


#define MAX_SIZE 20
struct {
   fn_l2addr_t l2addr;
   fnaddr_t addr;
   event ev;
   void *l2frame;
} __attribute__((packed)) arp_table[MAX_SIZE];


typedef struct {
      uint32_t echoType;
} __attribute__((packed)) Echo;

void find_proto(int );
int find_addr(fnaddr_t);
void print_arp_table() ;
void destroy(void *);
void add_arp_entry(fn_l2addr_t, fnaddr_t , int);
void arp_resolve(fn_l2addr_t, void *param);
void arp_received(void *);
int fishnode_l2_receive(void *);
int fish_l2_send(void *, fnaddr_t, int);
void send_arp_request(fnaddr_t);
#endif
