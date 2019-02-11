#include "smartalloc.h"
#include "fish.h"
#include "fishnode.h"

#include <assert.h>
#include <signal.h>
#include <string.h>

static int noprompt = 0;

uint8_t count = 0;

void destroy(void *addr) {
   int i;
   fnaddr_t ip = *(fnaddr_t*)addr;
   for( i=0; i< MAX_SIZE; i++){
      if (arp_table[i].addr == ip){
         count--;
         fprintf(stderr, "ENTRY DESTROYED\n\n");
         memset(&arp_table[i], 0, sizeof(arp_table[0]));
         return;
      }
   }
}

void find_proto(int index) {
   u_char* frame = (u_char*)(arp_table[index].l2frame); 
   l2_header_t *l2header = (l2_header_t*)frame;
   l3_header_t *l3header = (l3_header_t*)(frame + sizeof(l2_header_t));
   int len = ntohs(l2header->len);
   fprintf(stderr, "\n\nPROTOCOL is %d\n", l3header->proto);
   arp_resolve(arp_table[index].l2addr, arp_table[index].l2frame);
   if (l3header->proto == 2) {
      fprintf(stderr, "LENGTH of THE ORIGINAL FRAME is %d\n", ntohs(l2header->len));
      void *l2frame = malloc(len);
      memcpy(l2frame, (void*)frame, ntohs(l2header->len));
      Echo *echo = (Echo*)(l2frame + sizeof(l2_header_t) + sizeof(l3_header_t));
      fprintf(stderr, "Frames %s\n", 
                (0 == memcmp((void*)frame, l2frame, ntohs(l2header->len))) 
                           ? "Match" : "no match");
      echo->echoType = htonl(2);
      l2_header_t* newl2frame = (l2_header_t*)l2frame;
      fprintf(stderr, "LENGTH of NEW FRAME is %d\n", ntohs(newl2frame->len));
      arp_resolve(arp_table[index].l2addr, l2frame);
      return;
   }
}

int find_addr(fnaddr_t addr){
   int i;
   for(i = 0; i< MAX_SIZE; i++) {
      if ( arp_table[i].addr ==  addr ) {
         fish_cancelevent(arp_table[i].ev);
         arp_table[i].ev = fish_scheduleevent(180000, destroy, (void*)&arp_table[i]);
         find_proto(i);
         return 1;
      }
   }
   return 0;
}

void print_arp_table() {
   int i;
   fprintf(stderr, "\nMY ARP TABLE\n");
   for(i=0; i<MAX_SIZE;i++) {
      if (arp_table[i].addr != 0){         
         fprintf(stderr, "\n\nl2address is %s\n", fnl2_ntoa(arp_table[i].l2addr));
         fprintf(stderr, "L3address is %s\n", fn_ntoa(arp_table[i].addr));         
      }
   }
   fprintf(stderr, "\n");
}

void add_arp_entry(fn_l2addr_t l2addr, fnaddr_t addr, int timeout) {
   int i;
   event ev;
   
   //Check if the address is not present
   if (find_addr(addr))
      return;

   count++;
   for (i=0; i< MAX_SIZE; i++) {
      if ( arp_table[i].addr == 0 ) {
         arp_table[i].addr = addr;
         memcpy(&(arp_table[i].l2addr), &l2addr, sizeof(fn_l2addr_t));
         ev = fish_scheduleevent(timeout * 1000, destroy, (void*)&arp_table[i]);
         arp_table[i].ev = ev;
         find_proto(i);
         return;
      }
   }
   fprintf(stderr, "I GET HERE OUTSIDE?\n");
   arp_table[0].addr = addr;
   memcpy(&arp_table[0].l2addr,&l2addr, sizeof(fn_l2addr_t));
   arp_table[0].ev = fish_scheduleevent(timeout * 1000, destroy, (void*)&arp_table[0]);
   find_proto(0);
   return;
}

void arp_resolve(fn_l2addr_t addr, void *param) {
   if (!FNL2_VALID(addr)) {
      fish_debugframe(2, "ARP RESOLVE INVALID", param, 2, 10, 9);
      free(param);
      return;
   }

   l2_header_t *l2frame = (l2_header_t *)param;
   l2frame->dst = addr;
   l2frame->src = fish_getl2address();
   l2frame->cksum = 0x0;
   l2frame->cksum = in_cksum(param, ntohs(l2frame->len));

#ifdef DEBUG
fprintf(stderr, "\nADDRESS WAS RESOLVED\n");
fish_debugframe(2, "RESOLVED L2ADDR", param, 2, 20, 9);
#endif

   if (FNL2_VALID(addr)) {
      fish_l1_send(param);
   }
   free(param);
}

void arp_received(void *l2frame) {

   l2_header_t *l2_header = (l2_header_t*) l2frame;
   l3_header_t *l3_header = (l3_header_t *)((u_char*)l2frame + sizeof(l2_header_t));
   arp_t *arp = (arp_t*)((u_char*)l2frame +sizeof(l2_header_t)+ sizeof(l3_header_t));

   fnaddr_t addr = fish_getaddress();
   fn_l2addr_t l2addr = fish_getl2address();
   if (ntohl(arp->query) == 2) { 
      //fish_debugframe(2, "ARP_RESPONSE", l2frame, 2, 10,9);
      fish_arp.add_arp_entry(arp->l2addr, arp->l3addr, 180); 
      return;
   }
   //fish_debugframe(2, "ARP_REQUEST", l2frame, 2, 10,9);
   int len = ntohs(l2_header->len);

   //only process if it is destined for this node and if it is a request
   if ((addr == arp->l3addr) && (ntohl(arp->query) == 1)) {
      // if it is the same node asking for response return
      //fish_debugframe(2,"L2FRAME:DEBUG", l2frame, 2, 10, 9);

      void *new_l2frame = malloc(len);
      //set the l2header
      l2_header_t* new_l2header = (l2_header_t *) new_l2frame;
      new_l2header->src = l2addr;
      new_l2header->dst = l2_header->src;
      new_l2header->len = htons(len);
      new_l2header->cksum = 0;

      //Set L3header
      l3_header_t * new_l3frame = (l3_header_t*)((u_char*)new_l2frame + sizeof(l2_header_t));
      new_l3frame->src = addr;
      new_l3frame->dst = l3_header->src;
      new_l3frame->ttl = 1;
      new_l3frame->proto = 9;
      new_l3frame->packet_id = htons(fish_next_pktid());

      //Set ARP Response header
      arp_t* new_arp = (arp_t *)((u_char*)new_l2frame + sizeof(l2_header_t) + sizeof(l3_header_t));
      new_arp->l3addr = fish_getaddress();
      new_arp->l2addr = l2addr;
      new_arp->query = arp->query << 1;
      new_l2header->cksum = in_cksum((void*)new_l2header, len);
      
      //fish_debugframe(2,"NEW L2FRAME:DEBUG", new_l2header, 2, 10, 9);
      fish_l1_send(new_l2frame);
 
      free(new_l2frame);
   }
}

int fishnode_l2_receive(void *l2frame) {
   l2_header_t *l2_header = (l2_header_t*) l2frame;
   fn_l2addr_t l2addr = fish_getl2address();
   l3_header_t *l3_header = (l3_header_t*)((u_char*)l2frame + sizeof(l2_header_t));
   uint8_t proto = l3_header->proto;

   if (in_cksum(l2frame, ntohs(l2_header->len)) != 0)
      return FALSE;

   if ((!FNL2_EQ(l2addr, l2_header->dst)) &&
      (!FNL2_EQ(ALL_L2_NEIGHBORS, l2_header->dst)))
      return FALSE;

   int len = ntohs(l2_header->len) - sizeof(l2_header_t);

   if (proto == 9) {
      fprintf(stderr, "PROTOCOL was ARP\n");
      arp_received(l2frame);
      return TRUE;
   }
   else {
      fprintf(stderr, "PROTO WAS SOMETHING ELSE %d\n", proto);
      fish_l3.fish_l3_receive((void*)l3_header, len);
      //fish_debugframe(2, "\nFISHNODE L3 RECEIVED", l2frame, 2, 20, 9);
      return TRUE;
   }
}

int fish_l2_send(void *l3frame, fnaddr_t next_hop, int len) {
   void *l2frame = malloc(len +sizeof(l2_header_t));
   l2_header_t *l2_header= (l2_header_t*)l2frame;
   l2_header->len = htons(len + sizeof(l2_header_t));

   memcpy((u_char*)l2frame +sizeof(l2_header_t), l3frame, len);
   arp_table[count].l2frame = l2frame;
   fish_arp.resolve_fnaddr(next_hop, arp_resolve, l2frame);

   return TRUE;
}

void send_arp_request(fnaddr_t l3addr) {
   int len = sizeof(arp_t) + sizeof(l3_header_t) + sizeof(l2_header_t);

   void *l2frame = malloc(len);
   l2_header_t *l2_header = (l2_header_t*) l2frame;
   l2_header->src = fish_getl2address();
   l2_header->dst = ALL_L2_NEIGHBORS;
   l2_header->len = htons(len);
   l2_header->cksum = 0x0;

   l3_header_t *l3_header = (l3_header_t*)(l2frame + sizeof(l2_header_t));
   l3_header->ttl = 1;
   l3_header->proto = 9;
   l3_header->packet_id = htons(fish_next_pktid());
   l3_header->dst = ALL_NEIGHBORS;
   l3_header->src = fish_getaddress();

   arp_t *arp = (arp_t*)(l2frame + sizeof(l2_header_t) + sizeof(l3_header_t));
   arp->query = htonl(1);
   arp->l3addr = l3addr;
   memset(&(arp->l2addr), 0, sizeof(fn_l2addr_t));

   l2_header->cksum = in_cksum(l2frame, len);
   //fish_debugframe(2, "SENDING_ARP_REQUEST", l2frame, 2, len,  9);
   fish_l1_send(l2frame);
   free(l2frame);
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
      print_arp_table();
      //fish_print_arp_table();
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

   fish_l2.fishnode_l2_receive = fishnode_l2_receive;
   fish_l2.fish_l2_send = fish_l2_send;
   fish_arp.arp_received = arp_received;
   fish_arp.send_arp_request = send_arp_request;
   //fish_arp.add_arp_entry = add_arp_entry;

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

	printf("Fishnode exiting cleanly.\n");

	return 0;
}
