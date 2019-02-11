#include "smartalloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <assert.h>

#define TRUE             1
#define FALSE            0

#ifndef BUFSIZ
#define BUFSIZ           1024
#endif

char *res = "HTTP/1.0 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\n";
const char *idx = "<HTML><HEAD><TITLE>Index File</TITLE></HEAD>\n<BODY>\nSimple index file!\n</BODY>\n</HTML>\n\n";
const char *notFound = "<HTML><HEAD><TITLE>HTTP ERROR 404</TITLE></HEAD><BODY>404 Not Found.  Your request could not be completed due to encountering HTTP error number 404.</BODY></HTML>";

const char *implemented = "[\n{ \"feature\": \"about\", \"URL\": \"/json/about.json\"},{ \"feature\": \"quit\", \"URL\": \"/json/quit\"},{ \"feature\": \"status\", \"URL\": \"/json/status.json\"},{ \"feature\": \"fortune\", \"URL\": \"/json/fortune\"}]\n";
const char *about ="{\n  \"author\": \"John Bellardo\",  \"email\": \"bellardo@calpoly.edu\",  \"major\": \"CSC\"\n}\n"; 
const char *quit = "{\n  \"result\": \"success\"\n}\n";
char *status = "{\n \"num_clients\": %d,\n \"num_requests\": %d,\n \"errors\": %d,\n \"uptime\": %f,\n \"cpu_time\": %f,\n \"memory_used\": %lu\n}\n";
char *fortune = "{\n \"fortune\": \"%s\"}\n";

static int clients = 0;
static int err = 0;
static int numReq = 0;

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

static int fork_and_exec() {
   int fd[2];
   pid_t pid;
   int status;
   char buf[BUFSIZ];
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
      printf("changing loop\n");
      loop = sig;
   }
}

int main (int argc, char *argv[])
{
   int sfd, s, fortune_socket;
   int max_sd, desc_ready;
   int n, i, fd = -1;
   struct sockaddr_in6 addr, clientaddr;
   socklen_t addrlen = sizeof addr;
   char *line;
   char *word;
   
   struct timeval timeout;
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

   sfd = socket(AF_INET6, SOCK_STREAM, 0);
   if (sfd == -1)
      abort ();
   
   s = make_socket_non_blocking (sfd);
   if (s == -1)
      abort ();
   
   memset(&addr, 0, sizeof(addr));
   addr.sin6_family = AF_INET6;

   if (argc > 1) {
      struct addrinfo hint, *res = NULL;
      int ret;
  
      memset(&hint, '\0', sizeof hint);

      hint.ai_family = PF_UNSPEC;
      hint.ai_flags = AI_NUMERICHOST;

      ret = getaddrinfo(argv[1], NULL, &hint, &res);
      if (ret) {
          puts("Invalid address");
          puts(gai_strerror(ret));
          return 1;
      }
      if(res->ai_family == AF_INET) {
         printf("%s is an ipv4 address\n",argv[1]);
      }
      else if (res->ai_family == AF_INET6) {
         printf("%s is an ipv6 address\n",argv[1]);
      }
      else {
         printf("%s is an is unknown address format %d\n",argv[1],res->ai_family);
      }
   }
   else {
      addr.sin6_addr = in6addr_any;
   }
   addr.sin6_port = htons(0);
   
   s = bind(sfd, (struct sockaddr *)&addr, sizeof(addr));
   
   if (s == -1)  {
      close(sfd);
      abort ();
   }
   
   s = listen (sfd, SOMAXCONN);
   if (s == -1)
   {
      perror ("listen");
      abort ();
   }
   
   timeout.tv_sec  = 3 * 60;
   timeout.tv_usec = 0;
   
   FD_ZERO(&master_set);
   max_sd = sfd;
   FD_SET(sfd, &master_set);
   
   if (getsockname(sfd, (struct sockaddr*) &clientaddr, &addrlen) == -1) {
      perror("getsockname()");
      exit(EXIT_FAILURE);
   }
   printf("HTTP server running on TCP port %d\n", ntohs(clientaddr.sin6_port));
   printf("HTTPS server running on TCP port -1\n");

   /* The event loop */
   while (!loop)
   {
      memcpy(&working_set, &master_set, sizeof(master_set));
      n = select(max_sd + 1, &working_set, NULL, NULL, &timeout);
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
               while (TRUE) {
                  int infd;
                  infd = accept (sfd,NULL, NULL);
                  if (infd == -1) {
                     if ((errno != EAGAIN) ||
                         (errno != EWOULDBLOCK)) {
                        perror("accept()");
                     }
                     break;
                  }
                  ++clients;
                  printf("Connected filedes is %d\n", infd);
                  /* Make the incoming socket non-blocking and add it to the
                   list of fds to monitor. */
                  s = make_socket_non_blocking (infd);
                  if (s == -1) {
                     exit(EXIT_FAILURE);
                  }
                  
                  FD_SET(infd, &master_set);
                  if (infd > max_sd) {
                     max_sd = infd;
                  }
               }
            }
            else {
               /* We have data on the fd waiting to be read. Read and
                process it. */
               int done = FALSE;
               while (!done) {
                  ssize_t count;
                  char buf[BUFSIZ];
                  memset(buf, 0, sizeof buf);
                  count = read(i, buf, sizeof buf);
                  if (count < 0) {
                     if (errno != EWOULDBLOCK) {
                        done = TRUE;
                     }
                     break;
                  }
                  if (count == 0)
                  {
                     /* End of file. The remote has closed the
                      connection. */
                     done = TRUE;
                     break;
                  }

                  if (i == fd) {
                     // then send buf back
                     // send the header first
                     char msg[BUFSIZ];
                     memset(msg, 0, sizeof msg);
                     sprintf(msg, fortune, buf);
                     int len = strlen(msg);
                     memset(buf, 0, sizeof buf);
                     sprintf(buf, res, 200 , "OK", "application/json", len);
                     count = send(fortune_socket, buf, strlen(buf), 0);
                     if (count < 0) {
                        if (errno != EWOULDBLOCK || errno != EAGAIN) {
                           done = TRUE;
                        }
                        break;
                     }
                     count = 0;
                     int sent = 0;
                     while (count <len) {
                        sent = send(fortune_socket,msg, len, 0);
                        if (count < 0) {
                           if (errno != EWOULDBLOCK || errno != EAGAIN) {
                              done = TRUE;
                           }
                           break;
                        }
                        count += sent ;
                     }
                     done = TRUE;
                     close(fortune_socket);
                     FD_CLR(fortune_socket, &master_set);
                     if (fortune_socket == max_sd)
                     {
                        while (FD_ISSET(max_sd, &master_set) == FALSE)
                           max_sd -= 1;
                      }
                     break;
                  }

                  ++numReq;
                  line = strtok(buf, "\r\n"); 
                  word = strtok(line, " ");

                  /* Only process if GET*/
                  if (strcmp(word, "GET") == 0) {
                     word = strtok(NULL, " ");
                     if ((strcmp(word, "/") == 0 ) || (strcmp(word, "/index.html") ==0)) {
                        memset(buf, 0, sizeof buf);
                        int len = strlen(idx);
                        sprintf(buf, res, 200, "OK", "text/html",len);
                        count = send(i, buf, strlen(buf), 0); // Send the header
                        if (count < 0) {
                           if (errno != EWOULDBLOCK ||
                               errno != EAGAIN) {
                              done = TRUE;
                           }
                           break;
                        }
                        int sent = 0;
                        count = 0;
                        while (count < len) {
                           sent = send(i, idx, len, 0);
                           if (sent <0) {
                              if (errno != EAGAIN) {
                                 done = TRUE;
                              }
                              break;
                           }
                           count += sent;
                        }
                        done = TRUE;
                     }

                     else if (strcmp(word, "/json/implemented.json") == 0) {
                        memset(buf, 0, sizeof buf);
                        int len = strlen(implemented);
                        sprintf(buf, res, 200,"OK","application/json", len);
                        count = send(i, buf, strlen(buf), 0);
                        if (count < 0) {
                           if (errno != EAGAIN) {
                              done = TRUE;
                           }
                           break;
                        }
                        int sent = 0;
                        count = 0;
                        while (count < len) {
                           sent = send(i, implemented, strlen(implemented), 0);
                           if (sent < 0) {
                              if (errno != EAGAIN) {
                                 done = TRUE;
                              }
                              break;
                           }
                           count += sent;
                        }
                        done = TRUE;
                     }/* Send implemented json */
                     else if (strcmp(word, "/json/about.json") == 0) {
                        memset(buf, 0, sizeof buf);
                        int len = strlen(about);
                        sprintf(buf, res, 200, "OK", "application/json", len);
                        count = send(i, buf, strlen(buf), 0);
                        if (count < 0) {
                           if (errno != EAGAIN) {
                              done = TRUE;
                           }
                           break;
                        }

                        int sent = 0;
                        count = 0;
                        while(count <len) {
                           sent = send(i, about, len, 0);
                           if (sent < 0) {
                              if (errno != EAGAIN) {
                                 done = TRUE;
                              }
                              break;
                           }
                           count += sent;
                        }
                        done = TRUE;
                     }
                     else if (strcmp(word, "/json/quit") == 0) {
                        memset(buf, 0, sizeof buf);
                        int len = strlen(quit);
                        sprintf(buf, res, 200, "OK", "application/json", len);
                        count = send(i, buf, strlen(buf), 0);
                        if (count < 0) {
                           if (errno != EAGAIN) {
                              done = TRUE;
                           }
                           break;
                        }
                        int sent = 0;
                        count = 0;
                        while(count <len) {
                           sent = send(i, quit, len, 0);
                           if (sent < 0) {
                              if (errno != EAGAIN) {
                                 done = TRUE;
                              }
                              break;
                           }
                           count += sent;
                        }
                        done = TRUE;
                        exit(EXIT_SUCCESS);
                     }
                     else if (strcmp(word, "/json/status.json") == 0) {
                        char header[BUFSIZ];
                        memset(header, 0, sizeof header);
                        memset(buf, 0, sizeof buf);
                        long size = get_memory_usage_linux();
                        struct rusage usage;

                        if(getrusage(RUSAGE_SELF, &usage) == -1) {
                           perror("Can't get usage\n");
                           break;
                        }

                        long ttime = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec;
                        long ctime = usage.ru_utime.tv_sec;

                        sprintf(buf, status, clients, numReq, err,ttime, ctime, size);
                        int len = strlen(buf);
                        sprintf(header, res, 200, "OK", "application/json", len);
                        printf("Length is %d\n", len);
                        count = send(i, header, strlen(header), 0);
                        if (count < 0) {
                           if (errno != EAGAIN) {
                              done = TRUE;
                           }
                           break;
                        }
                        int sent = 0;
                        count = 0;
                        while(count <= len) {
                           sent = send(i,buf,len, 0);
                           if (sent < 0) {
                              break;
                           }
                           count += sent;
                        }
                        done = TRUE;
                     }
                     else if (strcmp(word, "/json/fortune") == 0) {
                        fortune_socket = i;
                        fd = fork_and_exec();
                        s = make_socket_non_blocking (fd);
                        if (s == -1) {
                           exit(EXIT_FAILURE);
                        }
                        FD_SET(fd, &master_set);
                        if (fd > max_sd) {
                          max_sd = fd;
                        }                      
                     }
                     else {
                        ++err;
                        memset(buf, 0, sizeof buf);
                        int len = strlen(notFound);
                        sprintf(buf, res, 404, "NOT FOUND", "text/html", len);
                        count = send(i, buf, strlen(buf), 0);
                        if (count < 0) {
                           if (errno != EAGAIN ||
                              errno != EWOULDBLOCK) {
                              done = TRUE;
                           }
                           break;
                        }
                        count = 0;
                        int sent;
                        while(count < len) {
                           sent = send(i, notFound, len, 0);
                           if (sent < 0){ 
                              if (errno != EAGAIN || errno != EWOULDBLOCK) {
                                 done = TRUE;
                                 break;
                              }
                           }
                           count += sent;
                        }
                        done = TRUE; 
                     }
                  }
                  else { /* It's not GET*/
                     ++err;
                     memset(buf, 0, sizeof buf);
                     int len = strlen(notFound);
                     sprintf(buf, res, 404, "NOT FOUND", "text/html", len);
                     count = send(i, buf, strlen(buf), 0);
                     if (count < 0) {
                        if (errno != EAGAIN ||

                           errno != EWOULDBLOCK) {
                           done = TRUE;
                        }
                        break;
                     }
                     count = 0;
                     int sent;
                     while(count < len) {
                        sent = send(i, notFound, len, 0);
                        if (sent < 0){ 
                           if (errno != EAGAIN || errno != EWOULDBLOCK) {
                              done = TRUE;
                              break;
                           }
                        }
                        count += sent;
                     }
                     done = TRUE; 
                  }
               }
               if (done)
               {
                  close(i);
                  FD_CLR(i, &master_set);
                  if (i == max_sd)
                  {
                     while (FD_ISSET(max_sd, &master_set) == FALSE)
                        max_sd -= 1;
                  }
               }
            }
         }
      }
   }
   for (i=0; i <= max_sd; ++i)
   {
      if (FD_ISSET(i, &master_set))
         close(i);
   }

   printf("Server exiting cleanly.\n");
   return EXIT_SUCCESS;
}


