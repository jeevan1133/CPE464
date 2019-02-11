#include "smartalloc.h"
#include "fish.h"
#include "fishnode.h"

#include <assert.h>
#include <signal.h>
#include <string.h>

static int noprompt = 0;

int fish_l3_forward(void *l3frame, int len) {
   l3_header_t *l3header = (l3_header_t*)l3frame;
   if ((l3header->ttl <= 0)  &&
       (l3header->dst != fish_getaddress())) {
      fish_fcmp.send_fcmp_response(l3frame, len, 1);
      return FALSE;
   }
   fnaddr_t next_hop;
   if (0 == (next_hop = fish_fwd.longest_prefix_match(l3header->dst))) {
      fish_fcmp.send_fcmp_response(l3frame,len, 2);
      return FALSE;
   }
   fish_l2.fish_l2_send(l3frame, next_hop, len);
   return TRUE;
}

int frame_received(fnaddr_t src, uint32_t pkt) {
   src_pkt *temp = head ;
   while (temp != NULL) {
      if ((temp->src.src == src) &&(temp->src.pkt_id == pkt))
         return TRUE;
      temp  = temp->next;
   }
   return FALSE;
}

src_pkt *add_received(fnaddr_t src, uint32_t pkt) {
   src_pkt *temp = (src_pkt*)malloc(sizeof(src_pkt));
   temp->next = head;
   temp->src.pkt_id = pkt;
   temp->src.src = src;
   return temp;
}

int fishnode_l3_receive(void* l3frame, int len) {
   l3_header_t *l3_header = (l3_header_t*)l3frame;
   /* If the destination is for this fish node */
   if (l3_header->dst == fish_getaddress()) {
      //fish_debugframe(3, "FISH_L2_RECEIVE", l3frame, 3, len, l3_header->proto);
      fish_l4.fish_l4_receive(l3frame + sizeof(l3_header_t),
                              len-sizeof(l3_header_t),
                              l3_header->proto, l3_header->src);
      return TRUE;
   }
   int sent_already = frame_received(l3_header->src, l3_header->packet_id);
   /* IF broadcast  and not for this node */
   if (l3_header->dst == ALL_NEIGHBORS) {
      if (sent_already)
         return FALSE;

      l3_header->ttl -= 1;
      //fish_debugframe(3, "FISH_L5_RECEIVE", l3frame, 3, len, l3_header->proto);
      fish_l4.fish_l4_receive(l3frame + sizeof(l3_header_t),
                                    len - sizeof(l3_header_t),
                                    l3_header->proto, l3_header->src); 
      if (l3_header->src != ALL_NEIGHBORS) {
         fish_l3.fish_l3_forward(l3frame, len);
         head = add_received(l3_header->src, l3_header->packet_id);
      }
      return TRUE;
   }
   if (l3_header->src != ALL_NEIGHBORS) {
      l3_header->ttl -=  1;
      fish_l3.fish_l3_forward(l3frame, len);
      head = add_received(l3_header->src, l3_header->packet_id);
   }
   return TRUE;
}

int fish_l3_send(void *l4frame, int len, fnaddr_t dst_addr,
                 uint8_t proto, uint8_t ttl) {
   void *l3frame = malloc(len + sizeof(l3_header_t));
   l3_header_t *l3_header= (l3_header_t*)l3frame;
   if ((ttl > MAX_TTL) || (ttl == 0)){
      ttl = MAX_TTL;
   }
  
   l3_header->ttl = ttl;
   l3_header->proto = proto;
   l3_header->packet_id = htonl(fish_next_pktid());
   l3_header->src = fish_getaddress();
   l3_header->dst = dst_addr;
   memcpy((u_char*)l3frame + sizeof(l3_header_t), l4frame, len);
   int ret = fish_l3.fish_l3_forward(l3frame, len + sizeof(l3_header_t));
   free(l3frame);
   return ret;
}

void cleanup() {
   src_pkt *temp = head;
   src_pkt *prev = NULL;

   while (temp != NULL) {
      prev = temp;
      temp = temp->next ;
      free(prev);
   }
}

void* add_fwtable_entry(fnaddr_t dst,
                        int prefix_length,
                        fnaddr_t next_hop,
                        int metric, char type,
                        void *user_data)
{
   fwd_table_t *entry = malloc(sizeof (fwd_table_t));
   entry->next = fwd_table_head;
   entry->data = user_data;
   entry->dst = dst;
   entry->prefix_length = prefix_length;
   entry->next_hop = next_hop;
   entry->type = type;   
   entry->metric = metric;
   fwd_table_head = entry;
   return (void*)entry;
}

typedef struct long_match {
   fwd_table_t *entry;
   struct long_match *next;
} long_match;

long_match *prefix = NULL;

fnaddr_t find_best_match(long_match *entry) {
   fnaddr_t match = 0;
   long_match *temp = entry;
   long_match *prev = NULL;
   uint32_t pre = 0;
   int met = 0;
   while ( temp != NULL) {
      //check longest prefix
      if (pre < temp->entry->prefix_length) {
         pre = temp->entry->prefix_length;
         match = temp->entry->next_hop ;
         met = temp->entry->metric;
      }
      
      //if prefix match return with smallest metric
      else if (pre == temp->entry->prefix_length) {
         if (met > temp->entry->metric) {
            pre = temp->entry->prefix_length;
            match = temp->entry->next_hop ;
            met = temp->entry->metric;
         }
      }
      prev = temp;
      temp = temp->next;
      free(prev);
   }
   prefix = NULL;
   return match;
}

fnaddr_t longest_prefix_match(fnaddr_t addr) {
   fwd_table_t *temp = fwd_table_head;
   long_match *entry = NULL;
   
   while (temp != NULL)  {
      if (temp->dst == addr) {
         entry = (long_match*) malloc(sizeof(long_match));
         entry->entry = temp;
         entry->next = prefix;
         prefix = entry;
      }
      temp = temp->next;
   }
   return find_best_match(entry);
}

int check_entries(fwd_table_t *tbd, fwd_table_t *temp) {
   if (tbd->dst == temp->dst &&
      tbd->metric == temp->metric &&
      tbd->next_hop == temp->next_hop &&
      tbd->prefix_length == temp->prefix_length &&
      tbd->type == temp->type &&
      tbd->data == temp->data)
   {
      return 1;
   }
   
   return 0;
}

void* remove_fwtable_entry(void *route_key)
{
   fwd_table_t *temp = fwd_table_head;
   fwd_table_t *tbd = (fwd_table_t*)route_key;
   fwd_table_t *prev = NULL;
   void * data = NULL;
   
   while(temp != NULL) {
      if (check_entries(tbd, temp)) {
         data = temp->data;
         if (temp->next != NULL) {
            if (prev != NULL)
               prev->next = temp->next;
            else if (prev == NULL)
               fwd_table_head = temp->next;
            free(temp);
            break;
         }
         else if (temp->next == NULL) {
            if (prev != NULL)
               prev->next = NULL;
            else if (prev == NULL)
               fwd_table_head = NULL;
            free(temp);
            break;
         }
      }
      prev = temp;
      temp = temp->next;
   }
   return data;
}

int update_fwtable_metric(void *route_key, int new_metric) {
   fwd_table_t *temp = fwd_table_head;
   fwd_table_t *entry = (fwd_table_t*)route_key;
   while (temp != NULL) {
      if (check_entries(entry, temp)) {
         temp->metric = new_metric;
         return TRUE;
      }
      temp = temp->next;
   }
   return FALSE;
}

void reset_fwd_table() {
   fwd_table_t *temp = fwd_table_head;
   fwd_table_t *prev = NULL;
   while (temp != NULL) {
      prev = temp;
      temp = temp->next;
      free(prev);
   }
}

void sigint_handler(int sig)
{
   if (SIGINT == sig)
      fish_main_exit();
}

static void keyboard_callback(char *line)
{
   if (0 == strcasecmp("show neighbors", line))
      fish_print_neighbor_table();
   else if (0 == strcasecmp("show arp", line))
      fish_print_arp_table();
   else if (0 == strcasecmp("show route", line))
      fish_print_forwarding_table();
   else if (0 == strcasecmp("show dv", line))
      fish_print_dv_state();
   else if (0 == strcasecmp("quit", line) || 0 == strcasecmp("exit", line))
      fish_main_exit();
   else if (0 == strcasecmp("show topo", line))
      fish_print_lsa_topo();
   else if (0 == strcasecmp("help", line) || 0 == strcasecmp("?", line)) {
      printf("Available commands are:\n"
             "    exit                         Quit the fishnode\n"
             "    help                         Display this message\n"
             "    quit                         Quit the fishnode\n"
             "    show arp                     Display the ARP table\n"
             "    show dv                      Display the dv routing state\n"
             "    show neighbors               Display the neighbor table\n"
             "    show route                   Display the forwarding table\n"
             "    show topo                    Display the link-state routing\n"
             "                                 algorithm's view of the network\n"
             "                                 topology\n"
             "    ?                            Display this message\n"
             );
   }
   else if (line[0] != 0)
      printf("Type 'help' or '?' for a list of available commands.  "
             "Unknown command: %s\n", line);
   
   if (!noprompt)
      printf("> ");
   
   fflush(stdout);
}

int main(int argc, char **argv)
{
   struct sigaction sa;
   int arg_offset = 1;
   
   /* Verify and parse the command line parameters */
   if (argc != 2 && argc != 3 && argc != 4)
   {
      printf("Usage: %s [-noprompt] <fishhead address> [<fn address>]\n", argv[0]);
      return 1;
   }
   
   if (0 == strcasecmp(argv[arg_offset], "-noprompt")) {
      noprompt = 1;
      arg_offset++;
   }
   
   /* Install the signal handler */
   sa.sa_handler = sigint_handler;
   sigfillset(&sa.sa_mask);
   sa.sa_flags = 0;
   if (-1 == sigaction(SIGINT, &sa, NULL))
   {
      perror("Couldn't set signal handler for SIGINT");
      return 2;
   }
   
   /* Set up debugging output */
#ifdef DEBUG
   fish_setdebuglevel(FISH_DEBUG_ALL);
#else
   fish_setdebuglevel(FISH_DEBUG_NONE);
#endif
   fish_setdebugfile(stderr);
   
   fish_l3.fishnode_l3_receive = fishnode_l3_receive;
   fish_l3.fish_l3_forward = fish_l3_forward;
   fish_l3.fish_l3_send = fish_l3_send;
   fish_fwd.add_fwtable_entry = add_fwtable_entry;
   fish_fwd.longest_prefix_match = longest_prefix_match;
   fish_fwd.remove_fwtable_entry = remove_fwtable_entry;
   fish_fwd.update_fwtable_metric = update_fwtable_metric;

   /* Join the fishnet */
   if (argc-arg_offset == 1)
      fish_joinnetwork(argv[arg_offset]);
   else
      fish_joinnetwork_addr(argv[arg_offset], fn_aton(argv[arg_offset+1]));
   
   /* Install the command line parsing callback */
   fish_keybhook(keyboard_callback);
   if (!noprompt)
      printf("> ");
   fflush(stdout);
   
   /* Enable the built-in neighbor protocol implementation.  This will discover
    * one-hop routes in your fishnet.  The link-state routing protocol requires
    * the neighbor protocol to be working, whereas it is redundant with DV.
    * Running them both doesn't break the fishnode, but will cause extra routing
    * overhead */
   fish_enable_neighbor_builtin( 0
                                | NEIGHBOR_USE_LIBFISH_NEIGHBOR_DOWN
                                );
   
   /* Enable the link-state routing protocol.  This requires the neighbor
    * protocol to be enabled. */
   fish_enable_lsarouting_builtin(0);
   
   /* Full-featured DV routing.  I suggest NOT using this until you have some
    * reasonable expectation that your code works.  This generates a lot of
    * routing traffic in fishnet */
   
   fish_enable_dvrouting_builtin( 0
                                 | DVROUTING_WITHDRAW_ROUTES
                                 // | DVROUTING_TRIGGERED_UPDATES
                                 | RVROUTING_USE_LIBFISH_NEIGHBOR_DOWN
                                 | DVROUTING_SPLIT_HOR_POISON_REV
                                 | DVROUTING_KEEP_ROUTE_HISTORY
                                 );
   
   /* Execute the libfish event loop */
   fish_main();
   
   /* Clean up and exit */
   if (!noprompt)
      printf("\n");

   reset_fwd_table();
   cleanup();
   
   printf("Fishnode exiting cleanly.\n");
   
   return 0;
}
