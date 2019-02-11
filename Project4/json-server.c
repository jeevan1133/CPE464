#include "smartalloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <assert.h>
#include <time.h>

#define TRUE             1
#define FALSE            0
#define BUF_SIZ      1024

char *res = "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n";
const char *idx = "<HTML><HEAD><TITLE>Index File</TITLE></HEAD>\n<BODY>\nSimple index file!\n</BODY>\n</HTML>\n\n";
const char *notFound = "<HTML><HEAD><TITLE>HTTP ERROR 404</TITLE></HEAD><BODY>404 Not Found.  Your request could not be completed due to encountering HTTP error number 404.</BODY></HTML>";

const char *implemented = "[\n{ \"feature\": \"about\", \"URL\": \"/json/about.json\"},{ \"feature\": \"quit\", \"URL\": \"/json/quit\"},{ \"feature\": \"status\", \"URL\": \"/json/status.json\"},{ \"feature\": \"fortune\", \"URL\": \"/json/fortune\"}]\n";
const char *about ="{\n  \"author\": \"Jeevan Basnet\",  \"email\": \"jbasnet@calpoly.edu\",  \"major\": \"CSC\"\n}\n";
const char *quit = "{\n  \"result\": \"success\"\n}";
char *status = "{\n \"num_clients\": %d,\n \"num_requests\": %d,\n \"errors\": %d,\n \"uptime\": %f,\n \"cpu_time\": %f,\n \"memory_used\": %lu\n}\n";
char *fortune = "{\n \"fortune\": \"%s\"}\n";

static int clients = 0;
static int err = 0;
static int numReq = 0;

typedef struct {
   int bytesRead;
   char data[BUF_SIZ];
} conn_clients[SOMAXCONN];

conn_clients cnc;

static volatile sig_atomic_t loop = 0;

static long get_memory_usage_linux()
{
   // Variables to store all the contents of the stat file
   int pid, ppid, pgrp, session, tty_nr, tpgid;
   char comm[2048], state;
   unsigned int flags;
   unsigned long  minflt, cminflt, majflt, cmajflt, vsize;
   unsigned long utime, stime;
   long cutime, cstime, priority, nice, num_threads, itrealvalue, rss;
   unsigned long long starttime;
   // Open the file
   FILE *stat = fopen("/proc/self/stat", "r");
   if (!stat) {
      perror("Failed to open /proc/self/stat");
      return 0;
   }

   // Read the statistics out of the file
   fscanf(stat, "%d%s%c%d%d%d%d%d%u%lu%lu%lu%lu"
         "%ld%ld%ld%ld%ld%ld%ld%ld%llu%lu%ld",
         &pid, comm, &state, &ppid, &pgrp, &session, &tty_nr,
         &tpgid, &flags, &minflt, &cminflt, &majflt, &cmajflt,
         &utime, &stime, &cutime, &cstime, &priority, &nice,
         &num_threads, &itrealvalue, &starttime, &vsize, &rss);
   fclose(stat);
   return vsize;
}

static void send_err_msg(char*buf, int i) {
   ++err;
   size_t len = strlen(notFound);
   sprintf(buf, res, 404, "NOT FOUND", "text/html", len);
   size_t count = send(i, buf, strlen(buf), 0);
   if (count < 0) {
      if (errno != EAGAIN ||
            errno != EWOULDBLOCK) {
         return;
      }
   }
   count = 0;
   size_t sent;
   sent = send(i, notFound, len, 0);
   if (sent < 0){
      if (errno != EAGAIN || errno != EWOULDBLOCK) {
         return;
      }
   }
}

static int make_socket_non_blocking (int sfd)
{
   int flags, s;
   flags = fcntl (sfd, F_GETFL, 0);
   if (flags == -1)
   {
      perror ("fcntl");
      return -1;
   }

   flags |= O_NONBLOCK;
   s = fcntl (sfd, F_SETFL, flags);
   if (s == -1)
   {
      perror ("fcntl");
      return -1;
   }

   return 0;
}

static int fork_and_exec(int infd, int sfd) {
   int fd[2];
   pid_t pid;

   //Create a pipe first
   if (pipe(fd) == -1) {
      perror("pipe()");
      return -1;
   }

   //fork and exec
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

void sigint_handler(int sig) {
   if (SIGINT == sig) {
      loop = sig;
   }
}

int init_ipv4_socket(char* arg) {
   struct sockaddr_in ip4addr;
   int sfd, s;
   ip4addr.sin_family = AF_INET;
   ip4addr.sin_port = htons(0);
   if(inet_pton(AF_INET, arg, &ip4addr.sin_addr) != 1) {
      fprintf(stderr, "address '%s' didn't parse (v4 or v6)\n", arg);
      return -1;
   }

   sfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sfd == -1)
      abort ();

   s = make_socket_non_blocking (sfd);
   if (s == -1)
      abort ();

   if (inet_pton(AF_INET, arg, &ip4addr.sin_addr) != 1) {
      printf("address '%s' didn't parse (v4 or v6)\n", arg);
      exit(0);
   }

   if(bind(sfd, (struct sockaddr*)&ip4addr, sizeof ip4addr) == -1) {
      close(sfd);
      perror("Error binding TCP socket");
      return -1;
   }
   return sfd;
}

static int accept_connection(int sfd) {
   int infd = -1, s;
   infd = accept (sfd,NULL, NULL);
   if (infd == -1) {
      if ((errno != EAGAIN) ||
            (errno != EWOULDBLOCK)) {
         perror(NULL);
      }
      return infd;
   }
   ++clients;
   /* Make the incoming socket non-blocking*/
   s = make_socket_non_blocking (infd);
   if (s == -1) {
      return -1;
   }
   return infd;
}

char *fortune_file = "%s - - [%s%s\" 200"; 
char *fortune_ref;
char *fortune_agent;

char fortune_content[512];

int parse(char* buffer, int i, FILE *fp) {
   char *line = NULL;
   char buf[512];
   strncpy(buf, buffer, 512);
   ++numReq;
   char *refa = strstr(buf, "http:");
   char *agenta = strstr(refa, "User-Agent");
   refa = strtok(refa, "\r\n");
   agenta = strtok(agenta, " \r\n");
   agenta = strtok(NULL, "\r\n");
   char ref[64];
   char agent[64];
   strcpy(ref, refa);
   strcpy(agent, agenta);
   line = strtok(buf, " \r\n");
   int count;
   char temp[256];
   memset(temp, 0, 256);
   struct sockaddr_in6 client;
   socklen_t addrlen = sizeof(client);
   getpeername(i, (struct sockaddr *)&client, &addrlen);
   char str[INET6_ADDRSTRLEN];
   inet_ntop(AF_INET6, &client.sin6_addr, str, sizeof(str));
   strcpy(temp, str);
   strcat(temp, " - - [");
   time_t rawtime;
   struct tm * timeinfo;
   char time_buffer [80];

   time (&rawtime);
   timeinfo = localtime (&rawtime);

   strftime(time_buffer, 80, "%d/%b/%Y:%H:%M:%S %z] \"",timeinfo);
   strcat(temp, time_buffer);
   int sendLen = 0;
   int found = 404;
   if (strcmp(line, "GET") == 0) {
      strcat(temp, line);
      strcat(temp, " ");
      line = strtok(NULL, " \r\n");
      if (line == NULL) {
         send_err_msg(buf, i);
      }
      strcat(temp, line);
      strcat(temp, " HTTP/1.1\"");
      if ((strcmp(line, "/") == 0 ) ||
            (strcmp(line, "/index.html") ==0)) {
         int len = strlen(idx);
         found = 200;
         sprintf(buf, res, 200, "OK", "text/html",len);
         sendLen = len;
         int sent = 0;
         while (sent <strlen(buf)) {
            count = send(i, buf, strlen(buf), 0); // Send the header
            if (count < 0) {
               break;
            }
            sent += count;
         }
         sent = 0;
         count = 0;
         while (count < len) {
            sent = send(i, idx, len, 0);
            if (sent < 0) {
               return 0;
            }
            count += sent;
         }
      }//index
      else if (strcmp(line, "/json/implemented.json") == 0) {
         size_t len = strlen(implemented);
         sendLen = len;
         found = 200;
         sprintf(buf, res, 200,"OK","application/json", len);
         count = send(i, buf, strlen(buf), 0);
         if (count < 0) {
            return 0;
         }
         count = send(i, implemented, strlen(implemented), 0);
         if (count < 0) {
            return 0;
         }
      } //implementd.json
      else if (strcmp(line, "/json/about.json") == 0) {
         size_t len = strlen(about);
         sendLen = len;
         found = 200;
         sprintf(buf, res, 200, "OK", "application/json", len);
         count = send(i, buf, strlen(buf), 0);
         if (count < 0) {
            return 0;
         }
         count = send(i, about, len, 0);
         if (count < 0) {
            return 0;
         }
      }
      else if (strcmp(line, "/json/quit") == 0) {
         size_t len = strlen(quit);
         sendLen = len;
         found = 200;
         sprintf(buf, res, 200, "OK", "application/json", len);
         count = send(i, buf, strlen(buf), 0);
         if (count < 0) {
            return 0;
         }
         count = send(i, quit, len, 0);
         if (count < 0) {
            return 0;
         }
         loop = SIGINT;
      }
      else if (strcmp(line, "/json/status.json") == 0) {
         char *header = malloc(BUF_SIZ);
         long size = get_memory_usage_linux();
         struct rusage usage;

         if(getrusage(RUSAGE_SELF, &usage) == -1) {
            perror("Can't get usage\n");
            return 0;
         }

         long ttime = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec;
         long ctime = usage.ru_utime.tv_sec;

         sprintf(buf, status, clients, numReq, err,ttime, ctime, size);
         size_t len = strlen(buf);
         sendLen = len;
         found = 200;
         sprintf(header, res, 200, "OK", "application/json", len);
         count = send(i, header, strlen(header), 0);
         free(header);
         if (count < 0) {
            return 0;
         }
         count = send(i, buf,len, 0);
         if (count < 0) {
            return 0;
         }
      }
      else if (strcmp(line, "/json/fortune") == 0) {
         sprintf(fortune_content,fortune_file, str, 
                     time_buffer, "GET /json/fortune HTTP/1.1");
         fortune_ref = malloc(strlen(ref) +1);
         strcpy(fortune_ref, ref);
         fortune_ref[strlen(ref)] = '\0';
         fortune_agent = malloc(strlen(agent)+1);
         strcpy(fortune_agent, agent);
         fortune_agent[strlen(agent)] = '\0';
         return 1;
      }
      else {
         sendLen = 162;
         send_err_msg(buf, i);
      }
   } //GET
   else {
      sendLen = 162;
      send_err_msg(buf, i);
   }
   char cont_len [10];
   sprintf(cont_len, " %d %d", found, sendLen);
   strcat(temp, cont_len);
   strcat(temp, " \"");
   strcat(temp, ref);
   strcat(temp, "\" \"");
   strcat(temp, agent);
   strcat(temp, "\"");
   fputs(temp, fp);
   fputs("\n", fp);
   return 0;
}

int main (int argc, char *argv[])
{
   int sfd, s, fortune_socket = 0;
   int max_sd, desc_ready;
   int n, i, fd = -1;
   struct sockaddr_in6 addr;
   socklen_t addrlen = sizeof addr;

   fd_set master_set, working_set;

   struct sigaction sa;

   //Install Signal Handler
   sa.sa_handler = sigint_handler;
   sigfillset(&sa.sa_mask);
   sa.sa_flags = 0;
   if (-1 == sigaction(SIGINT, &sa, NULL)) {
      perror("Couldn't set signal handler for SIGINT");
      return 2;
   }

   memset(&addr, 0, sizeof addr);
   addr.sin6_family = AF_INET6;
   addr.sin6_port = 0;
   addr.sin6_addr = in6addr_any;
   int ipv6 = TRUE;
   if (argc > 1) {
      /* IPV4/IPV6 */
      if (inet_pton(AF_INET6, argv[1], &addr.sin6_addr) == 1) {
         ipv6 = TRUE;
      }
      else if (inet_pton(AF_INET6, argv[1], &addr.sin6_addr) == 1) {
         ipv6 = FALSE;
         sfd = init_ipv4_socket(argv[1]);
      }
      else {
         printf("address '%s' didn't parse (v4 or v6)\n", argv[1]);
         return 0;
      }
   }
   if (ipv6) {
      sfd = socket(AF_INET6, SOCK_STREAM, 0);
      if (sfd == -1) {
         perror(NULL);
         return 0;
      }
      s = make_socket_non_blocking (sfd);
      if (s == -1)
         abort ();

      if (bind(sfd, (struct sockaddr*)&addr, addrlen) == -1) {
         close(sfd);
         perror("Error binding TCP socket");
         return -1;
      }

   }
   s = listen (sfd, SOMAXCONN);
   if (s == -1)
   {
      perror (NULL);
      return -1;
   }

   fd_set writing_set, write_set;
   FD_ZERO(&master_set);
   FD_ZERO(&write_set);
   max_sd = sfd;
   FD_SET(sfd, &master_set);
   FD_SET(sfd, &write_set);

   if (getsockname(sfd, (struct sockaddr*) &addr, &addrlen) == -1) {
      perror("getsockname()");
      exit(EXIT_FAILURE);
   }

   printf("HTTP server is using TCP port %d\n", ntohs(addr.sin6_port));
   printf("HTTPS server is using TCP port -1\n");
   fflush(stdout);

   int count;
   int conn = 0;
   FILE *fp = fopen("access.log", "a");

   /* The event loop */
   while (!loop)
   {
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
                  means one or more incoming connections. */
               while(TRUE) {
                  int infd = accept_connection(sfd);
                  if (infd == -1) {
                     break;
                  }
                  conn++;
                  FD_SET(infd, &master_set);
                  if (infd > max_sd) {
                     max_sd = infd;
                  }
               }
            }
            else {
               /* We have data on the fd waiting to be read. Read and
                  process it. */
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
                  while (cnc[i-sfd-1].bytesRead < BUF_SIZ)
                  {
                     count = read(i, cnc[i-sfd-1].data + cnc[i-sfd-1].bytesRead, BUF_SIZ);
                     if (count < 0 )
                     {
                        if (errno == EWOULDBLOCK || errno == EAGAIN) {
                           if (!FD_ISSET(i, &writing_set)) {
                              FD_SET(i, &write_set);
                           }
                           break;
                        }
                        break;
                     }
                     if (count == 0) {
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
               fd = parse((char*)cnc[i-sfd-1].data, i, fp);
               if (fd) {
                  FD_CLR(i, &write_set);
                  fortune_socket = i;
                  fd = fork_and_exec(i, sfd);
                  s = make_socket_non_blocking(fd);
                  if (s == -1)
                     break;
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
   for (i=0; i <= max_sd; ++i)
   {
      if (FD_ISSET(i, &master_set))
         close(i);
   }
   fclose(fp);
   printf("Server exiting cleanly.\n");
   return 0;
}

