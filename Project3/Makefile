CC = gcc
CFLAGS = -g -Wall -Werror -DDEBUG
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX = $(OS)-$(PROC)
LDLIB = libfish-$(EXEC_SUFFIX).a

ifeq ("$(OS)", "SunOS")
   OSLIB=-L/opt/csw/lib -R/opt/csw/lib -lsocket -lnsl
   OSINC=-I/opt/csw/include
   OSDEF=-DSOLARIS
else
ifeq ("$(OS)", "Darwin")
   OSLIB=$(LDLIB)
   OSINC=
   OSDEF=-DDARWIN
else
   OSLIB=$(LDLIB)
   OSINC=
   OSDEF=-DLINUX
endif
endif

all:	fishnode-$(EXEC_SUFFIX)

debug:  DEBUG=-DDEBUG

debug:  fishnode-$(EXEC_SUFFIX)

fishnode-$(EXEC_SUFFIX):	fishnode.c
	$(CC) $(CFLAGS) $(DEBUG) $(OSINC) $(OSDEF) -o $@ fishnode.c smartalloc.c $(LDLIB)

handin:	README
	handin bellardo 464_p3 README fishnode.c fishnode.h smartalloc.c smartalloc.h Makefile libfish-Linux-x86_64.a fish.h

clean:
	-rm -rf fishnode-* fishnode-*.dSYM *.o
