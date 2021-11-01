/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.      *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2010 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

// and now we use it for serious purposes! YAY!

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include "pppoe.h"

#define BUFSIZE 1600
void my_err(char *msg, ...);

char* HU = "PC1";
short HUL = 3;

char *progname;
int debug = 1;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

void ifup(char* iname) {
 int sockfd;
 struct ifreq ifr;

 sockfd = socket(AF_INET, SOCK_DGRAM, 0);

 if (sockfd < 0)
    return;

 memset(&ifr, 0, sizeof ifr);

 strncpy(ifr.ifr_name, iname, IFNAMSIZ);

 ifr.ifr_flags |= IFF_UP;
 if( ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
  my_err("error bringing up %s\n",iname);
 }
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug) {
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

void hdbg(char *msg, ...) {
  va_list argp;
  va_start(argp, msg);
  fprintf(stderr, "[HDLR] ");
  vfprintf(stderr, msg, argp);
  va_end(argp);
}


/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -a <ifacename> -b <ifacename>\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-a <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-b <ifacename>: Name of interface to use (mandatory)\n");
  exit(1);
}

char LHU[256] = {0};
short LHUL = 0;
short SID = 0;

// handle PPPoE packets
void handle(unsigned char* buffer, int *l) {
  int lr = *l;
 struct ethhdr *hdr = (struct ethhdr*)buffer;
 if (hdr->h_proto == 0x6388) {
  struct padhdr *pad = (struct padhdr*)(buffer + sizeof(struct ethhdr));

  unsigned short sessid = ntohs(pad->sessid);
  unsigned short len = ntohs(pad->len);

  hdbg("PPPoE discovery packet, code=%d, sessid=%04X, len=%d\n",pad->code,sessid,len);

  if (pad->code == 9) { // PADI PACKET
   hdbg("Setting PPPoE Host-Uniq value to [");
   for (int i=0;i<HUL;i++) fprintf(stderr,"%02X",HU[i]);
   fprintf(stderr,", l=%d]\n",HUL);

   unsigned char* ptr = (unsigned char*)(buffer + sizeof(struct ethhdr) + sizeof(struct padhdr));
   while ((size_t)(buffer) < (size_t)(lr + (size_t)buffer)) {
    unsigned short a = ntohs(*(unsigned short*)ptr);
    unsigned short b = ntohs(*(unsigned short*)(ptr+2));

    if (a == 259) {
     *(unsigned short*)ptr = htons(261);
     memcpy(LHU, ptr+4, b);
     LHUL = b;
     hdbg("Old Host-Uniq: ");
     for (int k=0;k<LHUL;k++) fprintf(stderr,"%02X",LHU[k]);
     fprintf(stderr,"\n");
    }

    ptr+=1;
    if ((size_t)(ptr-buffer) >= lr) break;
   }

   *(unsigned short*)ptr = htons(259); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2); // extending packet (oooo)  
   *(unsigned short*)ptr = htons(HUL); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2);

   memcpy(ptr, HU, HUL); lr+=HUL; pad->len=htons(ntohs(pad->len)+HUL);

   *l = lr;
  } else if (pad->code == 7) { //PADO PACKET
   hdbg("Setting PADO Host-Uniq code\n");

   unsigned char* ptr = (unsigned char*)(buffer + sizeof(struct ethhdr) + sizeof(struct padhdr));
   while ((size_t)(buffer) < (size_t)(lr + (size_t)buffer)) {
    unsigned short a = ntohs(*(unsigned short*)ptr);
    unsigned short b = ntohs(*(unsigned short*)(ptr+2));

    if (a == 259) {
     *(unsigned short*)ptr = htons(261);
     hdbg("Modifying PADO Host-Uniq tag..\n");
    }

    ptr+=1;
    if ((size_t)(ptr-buffer) >= lr) {/*ptr = buffer + len;*/ break;}
   }

   *(unsigned short*)ptr = htons(259); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2); // extending packet (oooo)  
   *(unsigned short*)ptr = htons(LHUL); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2);

   memcpy(ptr, LHU, LHUL); lr+=LHUL; pad->len=htons(ntohs(pad->len)+LHUL); ptr+=LHUL;

   *l = lr;
  } else if (pad->code == 25) { //PADR PACKET
   hdbg("Setting PADR Host-Uniq tag\n");

   unsigned char* ptr = (unsigned char*)(buffer + sizeof(struct ethhdr) + sizeof(struct padhdr));
   while ((size_t)(buffer) < (size_t)(lr + (size_t)buffer)) {
    unsigned short a = ntohs(*(unsigned short*)ptr);
    unsigned short b = ntohs(*(unsigned short*)(ptr+2));

    if (a == 259) {
     *(unsigned short*)ptr = htons(261);
     hdbg("Modifying PADR Host-Uniq tag..\n");
    }

    ptr+=1;
    if ((size_t)(ptr-buffer) >= lr) {/*ptr = buffer + len;*/ break;}
   }

   *(unsigned short*)ptr = htons(259); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2); // extending packet (oooo)  
   *(unsigned short*)ptr = htons(HUL); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2);

   memcpy(ptr, HU, HUL); lr+=HUL; pad->len=htons(ntohs(pad->len)+HUL); ptr+=HUL;

   *l = lr;
  } else if (pad->code == 101) { //PADS PACKET
   printf("==> PADS SESSION ID = 0x%04X\n",sessid);
   SID = sessid;

   hdbg("Setting PADS Host-Uniq code\n");

   unsigned char* ptr = (unsigned char*)(buffer + sizeof(struct ethhdr) + sizeof(struct padhdr));
   while ((size_t)(buffer) < (size_t)(lr + (size_t)buffer)) {
    unsigned short a = ntohs(*(unsigned short*)ptr);
    unsigned short b = ntohs(*(unsigned short*)(ptr+2));

    if (a == 259) {
     *(unsigned short*)ptr = htons(261);
     hdbg("Modifying PADS Host-Uniq tag..\n");
    }

    ptr+=1;
    if ((size_t)(ptr-buffer) >= lr) {/*ptr = buffer + len;*/ break;}
   }

   *(unsigned short*)ptr = htons(259); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2); // extending packet (oooo)  
   *(unsigned short*)ptr = htons(LHUL); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2);

   memcpy(ptr, LHU, LHUL); lr+=LHUL; pad->len=htons(ntohs(pad->len)+LHUL); ptr+=LHUL;

   *l = lr;
  } else if (pad->code == 167) { //PADT PACKET
   hdbg("Setting PADT Host-Uniq code\n");

   unsigned char tp[256] = {0};
   unsigned char t2[256] = {0};
   memcpy(t2, HU, HUL);

   int ppr = 0;

   unsigned char* ptr = (unsigned char*)(buffer + sizeof(struct ethhdr) + sizeof(struct padhdr));
   while ((size_t)(buffer) < (size_t)(lr + (size_t)buffer)) {
    unsigned short a = ntohs(*(unsigned short*)ptr);
    unsigned short b = ntohs(*(unsigned short*)(ptr+2));

    if (a == 259) {
     *(unsigned short*)ptr = htons(261);
     hdbg("Modifying PADT Host-Uniq tag..\n");
     memcpy(tp, ptr+4, b);
     ppr = 1;
    }

    ptr+=1;
    if ((size_t)(ptr-buffer) >= lr) {/*ptr = buffer + len;*/ break;}
   }

   if (ppr) {
    if (!memcmp(tp, t2, 256)) {
     *(unsigned short*)ptr = htons(259); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2); // extending packet (oooo)  
     *(unsigned short*)ptr = htons(LHUL); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2);

     memcpy(ptr, LHU, LHUL); lr+=LHUL; pad->len=htons(ntohs(pad->len)+LHUL); ptr+=LHUL;
    } else {
     *(unsigned short*)ptr = htons(259); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2); // extending packet (oooo)  
     *(unsigned short*)ptr = htons(HUL); ptr+=2; lr+=2; pad->len=htons(ntohs(pad->len)+2);

     memcpy(ptr, HU, HUL); lr+=HUL; pad->len=htons(ntohs(pad->len)+HUL); ptr+=HUL;
    }
   }

   *l = lr;
  }
 }
}

int main(int argc, char *argv[]) {
  
  int tap1_fd, tap2_fd, option, nread, nwrite, maxfd;
  char i1_name[IFNAMSIZ] = "";
  char i2_name[IFNAMSIZ] = "";
  int flags = IFF_TAP;
  unsigned char buffer[1600];

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "a:b:h")) > 0) {
    switch(option) {
      case 'a':
        strncpy(i1_name,optarg, IFNAMSIZ-1);
        break;
      case 'b':
        strncpy(i2_name,optarg, IFNAMSIZ-1);
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  fprintf(stderr,"starting..\n");

  if(argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

  if(*i1_name == '\0' || *i2_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap1_fd = tun_alloc(i1_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface 1 %s!\n", i1_name);
    exit(1);
  }

  if ( (tap2_fd = tun_alloc(i2_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface 2 %s!\n", i2_name);
    exit(1);
  }

  ifup(i1_name);
  ifup(i2_name);

  char cmd[256];
  sprintf(cmd, "/usr/sbin/brctl addif br0 %s", i1_name);
  fprintf(stderr, "=> %s\n",cmd);
  system(cmd);
  sprintf(cmd, "/usr/sbin/brctl addif br1 %s", i2_name);
  fprintf(stderr, "=> %s\n",cmd);
  system(cmd);

  fprintf(stderr, "Successfully connected to interfaces %s/%s\n", i1_name, i2_name);

  /* use select() to handle two descriptors at once */
  maxfd = (tap1_fd > tap2_fd)?tap1_fd:tap2_fd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap1_fd, &rd_set); FD_SET(tap2_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap1_fd, &rd_set)) {
      /* data from tap1, write to tap2 */

      nread = cread(tap1_fd, buffer, BUFSIZE);

      handle(buffer, &nread);

      nwrite = cwrite(tap2_fd, buffer, nread);
    }

    if(FD_ISSET(tap2_fd, &rd_set)) {
      /* data from tap2, write to tap1 */

      nread = cread(tap2_fd, buffer, BUFSIZE);

      handle(buffer, &nread);

      nwrite = cwrite(tap1_fd, buffer, nread);
    }

  }

  return(0);
}
