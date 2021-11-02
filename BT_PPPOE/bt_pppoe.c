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
#include "control.h"

#define BUFSIZE 1600
void my_err(char *msg, ...);

char HU[17] = "PC1";
short HUL = 3;

int PORT = 3334;

char *progname;
int debug = 1;

#define CONTROL_MAGIC 0xBEEFF00DBEEFF00D

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
short SID = -1;

unsigned char ROUTER_MAC[8];
unsigned char ONT_MAC[8];

// handle control packets
void control(unsigned char* buffer, int *l, int *act, int *act2, unsigned char* retbuf, unsigned char* retbuf2) {
 int len = *l;
 if (len != sizeof(struct ctrlmsg)) {
  fprintf(stderr, "[CTRL] Got invalid control message of length %d\n",len);
  *l = 0;
  return;
 }

 struct ctrlmsg *msg = (struct ctrlmsg*)buffer;
 if (msg->magic != CONTROL_MAGIC) {
  fprintf(stderr, "[CTRL] Got invalid control message with magic 0x%16X\n",msg->magic);
  *l = 0;
  return;
 }

 if (msg->type == CTRL_SET_HOSTUNIQ) {
  int dlen = (msg->dlen > 16)?16:msg->dlen;
  fprintf(stderr, "[CTRL] Set Host_Uniq to ");
  for (int i=0;i<dlen;i++) fprintf(stderr, "%02X", msg->data[i]);
  fprintf(stderr, "\n");
  memcpy(HU, msg->data, dlen);
  HUL = dlen;
 } else if (msg->type == CTRL_GET_HOSTUNIQ) {
  fprintf(stderr, "[CTRL] Host_Uniq requested via control\n");
  msg->type = CTRL_RESP_HOSTUNIQ;
  memset(msg->data, 0, 16);
  memcpy(msg->data, HU, HUL);
  msg->dlen = HUL;

  *l = sizeof(struct ctrlmsg);

  return;
 } else if (msg->type == CTRL_GET_LASTHOSTUNIQ) {
  fprintf(stderr, "[CTRL] LAST Host_Uniq requested via control socket\n");
  msg->type = CTRL_RESP_LASTHOSTUNIQ;
  memset(msg->data, 0, 16);
  memcpy(msg->data, LHU, LHUL);
  msg->dlen = LHUL;

  *l = sizeof(struct ctrlmsg);

  return;
 } else if (msg->type == CTRL_GET_SESSID) {
  fprintf(stderr, "[CTRL] PPPoE session ID requested via control socket\n");

  msg->type = CTRL_RESP_SESSID;
  memset(msg->data, 0, 16);
  msg->dlen = 2;
  memcpy(msg->data, &SID, 2);

  *l = sizeof(struct ctrlmsg);

  return;
 } else if (msg->type == CTRL_SEND_PADT) {

  int dlen = (msg->dlen > 16)?16:msg->dlen;

  memset(retbuf, 0, 256);
  memset(retbuf2, 0, 256);

  int off = sizeof(struct ethhdr) + sizeof(struct padhdr) + 4;

  struct ethhdr* pakhdr = (struct ethhdr*)retbuf;
  struct padhdr* padhdr = (struct padhdr*)(retbuf + sizeof(struct ethhdr));

  padhdr->code = 167;
  padhdr->vertype = 0x11;
  padhdr->len = htons(HUL + 4 + 5);
  padhdr->sessid = htons(SID);

  memcpy(pakhdr->h_source, ROUTER_MAC, 6);
  memcpy(pakhdr->h_dest, ONT_MAC, 6);
  pakhdr->h_proto = htons(0x8863);

  retbuf[off-1] = HUL;
  retbuf[off-3] = 0x03;
  retbuf[off-4] = 0x01;
  memset(retbuf+off, 0, 16);
  memcpy(retbuf+off, HU, HUL);

  retbuf[off + HUL] = 0x01;
  retbuf[off + HUL + 1] = 0x05;
  retbuf[off + HUL + 2] = 0x00;


























  retbuf[off + HUL + 3] = 0x01;
  retbuf[off + HUL + 4] = 0xFF;

  memcpy(retbuf2, retbuf, 256);

  fprintf(stderr, "[CTRL] PPPoE PADT send requested via control socket [s=%d]\n",off+18);

  *act = off + HUL + 5;
  *act2 = off + HUL + 5;
 }

 *l = 0;
}

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
   memcpy(ROUTER_MAC, hdr->h_source, 6);

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
   memcpy(ONT_MAC, hdr->h_source, 6);

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

   printf("==> ROUTER: ");
   for (int i=0;i<5;i++) printf("%02X:",ROUTER_MAC[i]);
   printf("%02X  ONT: ",ROUTER_MAC[5]);
   for (int i=0;i<5;i++) printf("%02X:",ONT_MAC[i]);
   printf("%02X\n",ONT_MAC[5]);

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
  
/*  struct ctrlmsg kmsg;

  memset(&kmsg, 0, sizeof(struct ctrlmsg));

  kmsg.magic = CONTROL_MAGIC;
  kmsg.type = CTRL_SET_HOSTUNIQ;
  kmsg.dlen = 4;
  char *huk = "\x11\x12\x13\x14";
  memcpy(kmsg.data, huk, kmsg.dlen);

  unsigned char *qmsg = (unsigned char*)&kmsg;

  printf("=> ");
  for (int i=0;i<sizeof(struct ctrlmsg);i++) printf("%02X",qmsg[i]);
  printf("\n");

  exit(0);
*/
  int tap1_fd, tap2_fd, option, nread, nwrite, maxfd, sockfd;
  char i1_name[IFNAMSIZ] = "";
  char i2_name[IFNAMSIZ] = "";
  int flags = IFF_TAP;
  unsigned char buffer[1600];

  int slen = sizeof(struct sockaddr_in);

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

  struct sockaddr_in si_me, si_other;

  if ((sockfd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
   perror("socket()");
   exit(1);
  }

  memset((char *) &si_me, 0, sizeof(si_me));

  si_me.sin_family = AF_INET;
  si_me.sin_port = htons(PORT);
  si_me.sin_addr.s_addr = htonl(INADDR_ANY);

  if( bind(sockfd , (struct sockaddr*)&si_me, sizeof(si_me) ) == -1) {
    perror("bind()");
    exit(1);
  }

  fprintf(stderr, "Created control socket\n");

  /* use select() to handle two descriptors at once */
  maxfd = (tap1_fd > tap2_fd)?tap1_fd:tap2_fd;
  maxfd = (maxfd > sockfd)?maxfd:sockfd;

  int act = 0;
  int act2 = 0;
  unsigned char retbuf[257], retbuf2[257];

  while(1) {
    int ret;
    fd_set rd_set;

    nwrite = 0;

    FD_ZERO(&rd_set);
    FD_SET(tap1_fd, &rd_set); FD_SET(tap2_fd, &rd_set); FD_SET(sockfd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if (act2) {
        cwrite(tap2_fd, retbuf2, act2);
        printf("[CTRL] Sent retbuf2 [s=%d]\n", act2);
        act2 = 0;
    } else if (act) {
        cwrite(tap1_fd, retbuf, act);
        printf("[CTRL] Sent retbuf1 [s=%d]\n", act);
        act = 0;
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

    if(FD_ISSET(sockfd, &rd_set)) {
      nread = recvfrom(sockfd, buffer, BUFSIZE, 0, (struct sockaddr*)&si_other, &slen);
      if (nread<0) {
       perror("recvfrom()");
       exit(1);
      }

      printf("[CTRL] Read %d bytes from control socket\n",nread);
      control(buffer, &nread, &act, &act2, retbuf, retbuf2);

      if (nread>0) {
        nwrite = sendto(sockfd, buffer, nread, 0, (struct sockaddr*)&si_other, slen);
      }

    }
  }

  return(0);
}
