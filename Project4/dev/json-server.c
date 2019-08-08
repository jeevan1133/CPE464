#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#define FALSE (0)
#define TRUE !FALSE
#define BUF_SIZ 1024
#define FF "::ffff:"

static volatile sig_atomic_t loop = 0;

typedef struct {
   int bytesRead;
   char data[BUF_SIZ];
   char *addr;
   ushort port;
} conn_clients[SOMAXCONN];

char *res = "HTTP/1.0 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\n";
const char *idx = "<HTML><HEAD><TITLE>Index File</TITLE></HEAD>\n<BODY>\nSimple index file!\n</BODY>\n</HTML>\n\n";
const char *notFound = "<HTML><HEAD><TITLE>HTTP ERROR 404</TITLE></HEAD><BODY>404 Not Found.  Your request could not be completed due to encountering HTTP error number 404.</BODY></HTML>\n";
const char *implemented = "[\n{ \"feature\": \"about\", \"URL\": \"/json/about.json\"},{ \"feature\": \"quit\", \"URL\": \"/json/quit\"},{ \"feature\": \"status\", \"URL\": \"/json/status.json\"},{ \"feature\": \"fortune\", \"URL\": \"/json/fortune\"}]\n";
const char *about ="{\n  \"author\": \"John Bellardo\",  \"email\": \"bellardo@calpoly.edu\",  \"major\": \"CSC\"\n}\n";
const char *quit = "{\n  \"result\": \"success\"\n}";
char *status = "{\n \"num_clients\": %d,\n \"num_requests\": %d,\n \"errors\": %d,\n \"uptime\": %f,\n \"cpu_time\": %f,\n \"memory_used\": %lu\n}\n";
char *fortune = "{\n \"fortune\": \"%s\"}\n";

static int clients = 0;
static int err = 0;
static int numReq = 0;

conn_clients cnc;

static long get_memory_usage_linux() {
   /* Variables to store all the contents of the stat file */
   int pid, ppid, pgrp, session, tty_nr, tpgid;
   char comm[2048], state;
   unsigned int flags;
   unsigned long  minflt, cminflt, majflt, cmajflt, vsize;
   unsigned long utime, stime;
   long cutime, cstime, priority, nice, num_threads, itrealvalue, rss;
   unsigned long long starttime;
   /* Open the file */
   FILE *stat = fopen("/proc/self/stat", "r");
   if (!stat) {
      perror("Failed to open /proc/self/stat");
      return 0;
   }

   /* Read the statistics out of the file */
   fscanf(stat, "%d%s%c%d%d%d%d%d%u%lu%lu%lu%lu"
         "%ld%ld%ld%ld%ld%ld%ld%ld%llu%lu%ld",
         &pid, comm, &state, &ppid, &pgrp, &session, &tty_nr,
         &tpgid, &flags, &minflt, &cminflt, &majflt, &cmajflt,
         &utime, &stime, &cutime, &cstime, &priority, &nice,
         &num_threads, &itrealvalue, &starttime, &vsize, &rss);
   fclose(stat);
   return vsize;
}

void sigint_handler(int sig) {
   if (SIGINT == sig) {
      loop = sig;
   }
}

void setSignal() {

   struct sigaction sa;
   /*Install Signal Handler*/
   sa.sa_handler = sigint_handler;
   sigfillset(&sa.sa_mask);
   sa.sa_flags = 0;
   if (-1 == sigaction(SIGINT, &sa, NULL)) {
      perror("Couldn't set signal handler for SIGINT");
   }
}

static int make_socket_non_blocking (int sfd){
   int flags, s;
   flags = fcntl (sfd, F_GETFL, 0);
   if (flags == -1) {
      perror ("fcntl");
      return -1;
   }

   flags |= O_NONBLOCK;
   s = fcntl (sfd, F_SETFL, flags);
   if (s == -1) {
      perror ("fcntl");
      return -1;
   }
   return 0;
}

static void add_ipv4_client(struct sockaddr_in *sa, int conn) {
   char str[INET_ADDRSTRLEN];
   inet_ntop(AF_INET, (void *)&sa->sin_addr, str, INET_ADDRSTRLEN);
   char *addr = calloc(25, sizeof (char));
   strcat(strcpy(addr, FF), str);
   cnc[conn].addr = addr;
   cnc[conn].port = ntohs(sa->sin_port);
}

static void add_ipv6_client(struct sockaddr_in6 *sa, int conn) {
   socklen_t len = sizeof (*sa);
   char *buffer = malloc(INET6_ADDRSTRLEN);
   if (getnameinfo((struct sockaddr*)sa, len, buffer, sizeof(buffer), 0, 0, NI_NUMERICHOST)) {
      printf("Can't get address of client\n");
      return;
   }
   cnc[conn].addr = buffer;
   cnc[conn].port = ntohs(sa->sin6_port);
}

static int accept_connection(int sfd, int conn) {
   int infd = -1;
   struct sockaddr_storage client;
   socklen_t len = sizeof (client);
   infd = accept (sfd, (struct sockaddr *)&client, &len);
   if (infd == -1) {
      if ((errno != EAGAIN) ||
            (errno != EWOULDBLOCK)) {
         perror(NULL);
      }
      return infd;
   }
   if (client.ss_family==AF_INET) {
      add_ipv4_client((struct sockaddr_in*) &client, conn);
   }
   else {
      add_ipv6_client((struct sockaddr_in6*)&client, conn);
   }

   /* Make the incoming socket non-blocking*/
   if (make_socket_non_blocking (infd) == -1) {
      return -1;
   }
   return infd;
}

static void send_data(const char *buf, unsigned len, int desc) {
   int count = 0;
   int sent ;
   while(count < len){
      sent = (int)send(desc, buf, len, 0);
      if (sent < 0){
         if (errno != EAGAIN || errno != EWOULDBLOCK) {
            return;
         }
      }
      count += sent;
   }
}

static void send_err_msg(char *buf, int desc) {
   ++err;
   size_t len = strlen(notFound);
   sprintf(buf, res, 404, "NOT FOUND", "text/html", len);
   send_data((const char *)buf, (unsigned)strlen(buf), desc); /* Send Header */
   send_data(notFound, (unsigned)len, desc);  /* Send the data*/
}

static int fork_and_exec(int infd, int sfd) {
   int fd[2];
   pid_t pid;

   if (pipe(fd) == -1) {
      perror("pipe()");
      return -1;
   }

   if ((pid = fork()) == -1) {
      perror("fork()");
      return -1;
   }
   if (pid == 0)  { // Child process
      dup2(fd[1], STDOUT_FILENO);
      close(infd);
      close(sfd);
      close(fd[0]);
      close(fd[1]);
      execlp("/usr/bin/fortune","/usr/bin/fortune",(char*)0);
      exit(EXIT_FAILURE);
   }
   else {  // parent process
      close(fd[1]);
      return fd[0];
   }
}



char *fortune_file = "%s - - [%s%s\" 200";
char *fortune_ref;
char *fortune_agent;
char fortune_content[512];

int parse(char* buffer, int desc) {
   char *line = NULL;
   char buf[512];
   strncpy(buf, buffer, 512);
   line = strtok(buf, " ");
   char temp[256];
   memset(temp, 0, sizeof(temp));
   strcat(temp, " - - [");
   time_t rawtime;
   struct tm * timeinfo;
   char time_buffer [80];

   time (&rawtime);
   timeinfo = localtime (&rawtime);

   strftime(time_buffer, 80, "%d/%b/%Y:%H:%M:%S %z] \"",timeinfo);
   strcat(temp, time_buffer);
   int found = 200;
   if (strcmp(line, "GET") == 0) {
      strcat(temp, line);
      strcat(temp, " ");
      line = strtok(NULL, " \r\n");
      if (line == NULL) {
         send_err_msg(buf, desc);
      }
      strcat(temp, line);
      strcat(temp, " HTTP/1.1\"");
      ++numReq;
      if ((strcmp(line, "/") == 0 ) ||
            (strcmp(line, "/index.html") ==0)) {
         size_t len = strlen(idx);
         sprintf(buf, res, found, "OK", "text/html",len);
         send_data((const char *)buf, (unsigned) strlen(buf), desc);
         send_data(idx, (unsigned)len, desc);
      } //index
      else if (strcmp(line, "/json/implemented.json") == 0) {
         size_t len = strlen(implemented);
         sprintf(buf, res, found,"OK","application/json", len);
         send_data((const char *)buf, (unsigned)strlen(buf), desc);
         send_data(implemented, (unsigned)len, desc);
      } //implementd.json
      else if (strcmp(line, "/json/about.json") == 0) {
         size_t len = strlen(about);
         sprintf(buf, res, found, "OK", "application/json", len);
         send_data((const char *)buf, (unsigned) strlen(buf), desc);
         send_data(about, (unsigned) len, desc);
      }
      else if (strcmp(line, "/json/quit") == 0) {
         size_t len = strlen(quit);
         sprintf(buf, res, found, "OK", "application/json", len);
         send_data((const char *)buf, (unsigned) strlen(buf), desc);
         send_data(quit, (unsigned) len, desc);
         loop = SIGINT;
      }
      else if (strcmp(line, "/json/status.json") == 0) {
         char header[BUFSIZ];
         memset(header, 0, sizeof header);
         long size = get_memory_usage_linux();
         struct rusage usage;

         if(getrusage(RUSAGE_SELF, &usage) == -1) {
            perror("Can't get usage\n");
            return -1;
         }

         long ttime = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec;
         long ctime = usage.ru_utime.tv_sec;

         sprintf(buf, status, clients, numReq, err, ttime, ctime, size);
         size_t len = strlen(buf);
         sprintf(header, res, 200, "OK", "application/json", len);
         send_data(header, (unsigned)strlen(header), desc);
         send_data(buf, (unsigned)len, desc);
      }
      else if (strcmp(line, "/json/fortune") == 0) {
         sprintf(fortune_content,fortune_file, cnc[desc].addr,
               time_buffer, "GET /json/fortune HTTP/1.1");
         return 1;
      }

      else { /* If not one of the implemented */
         send_err_msg(buf, desc);
      }
   } /* If not GET */
   else {
      send_err_msg(buf, desc);
   }
   return 0;
}

int createAndBindSocket(char *name, struct addrinfo *hints) {
   struct addrinfo *servinfo = NULL, *p;
   int s, sfd = 0;
   memset(hints, 0, sizeof (*hints));
   hints->ai_socktype = SOCK_STREAM;
   hints->ai_flags = AI_PASSIVE | AI_V4MAPPED ; // use my IP address
   if ((s = getaddrinfo(name, NULL, hints, &servinfo)) != 0) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
      exit(1);
   }

   for(p = servinfo; p != NULL;  p = p->ai_next) {
      if ((sfd = socket(p->ai_family, p->ai_socktype,
                  p->ai_protocol)) == -1) {
         perror("socket");
         continue;
      }
      if (bind(sfd, p->ai_addr, p->ai_addrlen) == -1) {
         close(sfd);
         perror("bind");
      }
      break; // if we get here, we must have connected successfully
   }

   if (p == NULL) {
      perror(NULL);
      return -1;
   }
   freeaddrinfo(servinfo); /* all done with this structure */
   return sfd;
}

static int createIPV6Socket(struct sockaddr_in6 *addr) {
   int sfd ;
   socklen_t len = sizeof (*addr);
   addr->sin6_addr = in6addr_any;
   addr->sin6_port = htons(0);
   addr->sin6_family = AF_INET6;
   sfd = socket(AF_INET6, SOCK_STREAM, 0);

   if (bind(sfd, (struct sockaddr*)addr, len) == -1) {
      close(sfd);
      perror("Error binding TCP socket");
      exit(EXIT_FAILURE);
   }

   return sfd;
}

int main(int argc, char *argv[]) {

   setSignal();
   struct sockaddr_in6 addr;
   struct addrinfo hints;
   socklen_t len = sizeof(addr);

   int sfd = 0;
   int ipv6 = TRUE ;
   if (argc > 1) {
      memset(&hints, 0, sizeof hints);
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_PASSIVE | AI_V4MAPPED ; // use my IP address
      if (inet_pton(AF_INET6, argv[1], &addr.sin6_addr) == 1) {
         hints.ai_family = AF_INET6;
      }
      else {
         struct sockaddr_in ipaddr;
         if (inet_pton(AF_INET, argv[1], (struct sockaddr_in *)&ipaddr.sin_addr) != 1) {
            printf("address '%s' didn't parse (v4 or v6)\n", argv[1]);
            exit(0);
         }
         len = sizeof (ipaddr);
         ipv6 = FALSE;
         hints.ai_family = AF_INET;
      }
      sfd = createAndBindSocket(argv[1], &hints);
   }
   if (ipv6) {
      memset(&addr, '\0', len);
      sfd = createIPV6Socket(&addr) ;
   }
   if (make_socket_non_blocking (sfd) == -1) {
      perror("nonblock()");
      exit(EXIT_FAILURE);
   }
   if (listen(sfd, SOMAXCONN) == -1) {
      perror("listen()");
      exit(EXIT_FAILURE);
   }
   if (getsockname(sfd, (struct sockaddr*)&addr, &len) == -1) {
      perror("getsockname()");
      exit(EXIT_FAILURE);
   }
   printf("HTTP server is using TCP port %d\n", ntohs(addr.sin6_port));
   printf("HTTPS server is using TCP port -1\n");
   fd_set writing_set, write_set;
   fd_set master_set, working_set;
   FD_ZERO(&master_set);
   FD_ZERO(&write_set);
   int max_sd = sfd;
   FD_SET(sfd, &master_set);
   FD_SET(sfd, &write_set);

   int count;
   int conn = 0;
   int n, desc_ready,i, fd, fortune_socket = 0;
   FILE *fp = fopen("access.log", "a");
   /* The event loop */
   while (!loop) {
      memcpy(&working_set, &master_set, sizeof(master_set));
      memcpy(&writing_set, &write_set, sizeof(write_set));

      n = select(max_sd + 1, &working_set, &writing_set, NULL, NULL);
      if (n < 0) {
         break;
      }
      desc_ready = n ;
      for (i = 0; i <= max_sd  &&  desc_ready > 0; ++i) {
         if (FD_ISSET(i, &working_set)) {
            desc_ready -= 1;
            if (i == sfd) {
               /* We have a notification on the listening socket, which
                * means one or more incoming connections. */
               while(TRUE) {
                  int infd = accept_connection(sfd, conn);
                  if (infd == -1) {
                     break;
                  }
                  conn++;
                  ++clients;
                  FD_SET(infd, &master_set);
                  if (infd > max_sd) {
                     max_sd = infd;
                  }
               }
            }
            else {
               if (i == fd) {
                  char *msg = calloc(BUF_SIZ,sizeof(char));
                  char *buf = calloc(BUF_SIZ, sizeof (char));
                  while (TRUE) {
                     count = read(i, buf, BUF_SIZ);
                     if (count < 0 ) {
                        if (errno == EAGAIN)
                           break;
                     }
                  }
                  sprintf(msg, fortune, buf);
                  int len = strlen(msg);
                  memset(buf, 0, BUF_SIZ);
                  char *fort_log = malloc(2048);
                  char temp_len[5];
                  sprintf(temp_len," %d ", len);
                  strcpy(fort_log, fortune_content);
                  strcat(fort_log, temp_len);
                  strcat(fort_log, "\"");
                  strcat(fort_log, fortune_ref);
                  strcat(fort_log, "\" \"");
                  strcat(fort_log, fortune_agent);
                  strcat(fort_log, "\"");
                  fputs(fort_log, fp);
                  fputs("\n", fp);
                  free(fort_log);
                  free(fortune_ref);
                  free(fortune_agent);
                  sprintf(buf, res, 200, "OK","application/json", len);
                  len = strlen(buf);
                  count = send(fortune_socket, buf, len, 0); //response header
                  if (count <0) {
                     if (errno == EAGAIN)
                        break;
                  }
                  len = strlen(msg);
                  count = send(fortune_socket, msg, len, 0);
                  if (count <0) {
                     break;
                  }
                  close(fortune_socket);
                  FD_CLR(fortune_socket, &master_set);
                  free(buf);
                  free(msg);
                  fd = -1;
                  close(i);
                  --conn;
                  memset(&cnc[fortune_socket-sfd-1], 0, sizeof(cnc));
                  FD_CLR(i, &master_set);
                  if (i == max_sd) {
                     while(FD_ISSET(max_sd, &master_set) == FALSE)
                        max_sd -= 1;
                  }
                  if (fortune_socket == max_sd) {
                     while(FD_ISSET(max_sd, &master_set) == FALSE)
                        max_sd -=1;
                  }
                  break;
               }
               else {
                  while (cnc[i-sfd-1].bytesRead < BUF_SIZ) {
                     count = (int)read(i, cnc[i-sfd-1].data + cnc[i-sfd-1].bytesRead, BUF_SIZ);
                     if (count < 0 ) {
                        if (errno == EWOULDBLOCK || errno == EAGAIN) {
                           if (!FD_ISSET(i, &writing_set)) {
                              FD_SET(i, &write_set);
                           }
                           break;
                        }
                        break;
                     }
                     cnc[i-sfd-1].bytesRead += count;
                  }
               }
            }
         }
         else if (FD_ISSET(i, &writing_set)) {
            char c[5];
            memcpy(c, (cnc[i-sfd-1].data+cnc[i-sfd-1].bytesRead-4), 4);
            c[4] ='\0';
            if (strcmp(c, "\r\n\r\n") == 0) {
               fd = parse((char*)cnc[i-sfd-1].data, i);
               if (fd) {
                  FD_CLR(i, &write_set);
                  fortune_socket = i;
                  fd = fork_and_exec(i, sfd);
                  if (make_socket_non_blocking(fd) == -1) {
                     break;
                  }
                  FD_SET(fd, &master_set);
                  if (fd > max_sd) {
                     max_sd = fd;
                  }
                  break;
               }
            }
            else {
               FD_CLR(i, &write_set);
               break;
            }
            close(i);
            --conn;
            memset(&cnc[i-sfd-1], 0, sizeof cnc);
            FD_CLR(i, &master_set);
            FD_CLR(i, &write_set);
            if (i == max_sd) {
               while(FD_ISSET(max_sd, &master_set) == FALSE)
                  max_sd -= 1;
            }
         }
      }
   }
   for (i=0; i <= max_sd; ++i) {
      if (FD_ISSET(i, &master_set))
         close(i);
   }
   fclose(fp);
   printf("Server exiting cleanly.\n");
   return 0;
}


