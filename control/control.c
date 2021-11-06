#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include "../BT_PPPOE/control.h"
#include "../BT_PPPOE/pppoe.h"

#define BT_PPPOE_HOST "172.20.31.202"
#define BT_PPPOE_PORT 3334

#define RXBUFSIZ 1500

#define CONTROL_MAGIC 0xBEEFF00DBEEFF00D

char* pname;
char ifname[IFNAMSIZ] = "";
char buffer[BUFSIZ] = {0};

int sockfd;
int bpsock;

void help() {
 printf("usage: %s -a <ifname> -R <ip> -L <ip>\n",pname);
}

int main(int argc, char** argv) {
 printf("starting..\n");

 pname = argv[0];

 int opt;

 char li[16] = {0};
 char ri[16] = {0};

 while ((opt = getopt(argc, argv, "a:R:L:")) != -1) {
     switch (opt) {
     case 'a':
        strncpy(ifname, optarg, (strlen(optarg)>IFNAMSIZ)?IFNAMSIZ:strlen(optarg));
	break;
     case 'L':
        strncpy(li, optarg, (strlen(optarg)>16)?16:strlen(optarg));
        break;
     case 'R':
        strncpy(ri, optarg, (strlen(optarg)>16)?16:strlen(optarg));
        break;
     default:
         help();
         exit(EXIT_FAILURE);
     }
 }

 if (strlen(ifname)==0 || strlen(li) == 0 || strlen(ri) == 0) {
  help();
  exit(EXIT_FAILURE);
 }

 if (getuid()!=0) {
  printf("Must be UID 0!\n");
  exit(EXIT_FAILURE);
 }

 printf("Set interface: %s\n", ifname);

 sockfd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
 if (sockfd<0) {
  perror("socket():");
  exit(EXIT_FAILURE);
 }
 printf("Created raw socket\n");

 setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
 printf("Bound to interface %s\n", ifname);

 if ((bpsock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
  perror("socket creation failed");
  exit(EXIT_FAILURE);
 }
 printf("Created control socket\n");

 int nread = 0;

 while (1) {
  nread = recvfrom(sockfd, buffer, RXBUFSIZ, 0, NULL, NULL);

  struct ethhdr *ehdr = (struct ethhdr*)buffer;

  if (ehdr->h_proto != htons(0x8863)) continue;

  struct padhdr *phdr = (struct padhdr*)(buffer + sizeof(struct ethhdr));

  if (phdr->vertype != 0x11) continue;
  if (phdr->code != 0x9) continue;

  unsigned short hul = 0;
  char hostuniq[256];

  int i=0;
  for (;i< ntohs(phdr->len);i++) {
   size_t base = (size_t)phdr+sizeof(struct padhdr)+i;
   unsigned short a = 0;
   unsigned short b = 0;
   memcpy(&a, (unsigned char*)base, 2);
   memcpy(&b, (unsigned char*)base+2, 2);
   a=ntohs(a); b=ntohs(b);
   if (a == 259) {
    memcpy(hostuniq, (unsigned char*)base+4, (b>256)?256:b);
    hul = (b>256)?256:b;
    break;
   }
  }

  printf("Got PADI from ");
  for (int i=0;i<5;i++) printf("%02X:",ehdr->h_source[i]);
  printf("%02X, Host_Uniq=0x",(unsigned char)ehdr->h_source[5]);
  for (int i=0;i<hul;i++) printf("%02X",(unsigned char)hostuniq[i]);
  printf("\n");

  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  int slen = sizeof(servaddr);

  servaddr.sin_family    = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(BT_PPPOE_HOST);
  servaddr.sin_port = htons(BT_PPPOE_PORT);

  struct ctrlmsg cmsg;
  cmsg.magic = CONTROL_MAGIC;
  cmsg.type  = CTRL_SET_HOSTUNIQ;
  cmsg.dlen  = 4;
  memcpy(cmsg.data, hostuniq, 4);

  if (sendto(bpsock, &cmsg, sizeof(cmsg), 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
       perror("CTRL_SET_HOSTUNIQ: sendto():");
       exit(EXIT_FAILURE);
  }

  printf("Sent control message to BT_PPPOE [CTRL_SET_HOSTUNIQ]\n");

  cmsg.magic = CONTROL_MAGIC;
  cmsg.type  = CTRL_SEND_PADT;
  cmsg.dlen  = 0;

  if (sendto(bpsock, &cmsg, sizeof(cmsg), 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
       perror("CTRL_SEND_PADT: sendto():");
       exit(EXIT_FAILURE);
  }

  printf("Sent control message to BT_PPPOE [CTRL_SEND_PADT]\n");

  printf("Waiting for session event..\n");

  cmsg.magic = 0;

  while (ntohs(cmsg.type) != CTRL_EVENT_SESSIONID && cmsg.magic != CONTROL_MAGIC) {
   nread = recvfrom(bpsock, &cmsg, sizeof(cmsg), MSG_WAITALL, (struct sockaddr *) &servaddr, &slen);
   printf("Read %d bytes from control socket, t=%04X\n",nread,(cmsg.type));
  }

  unsigned short sessid = ((unsigned char)cmsg.data[0]<<8) + (unsigned char)cmsg.data[1];

  printf("Got sessid: %04X\n",sessid);

  char sessid_[8] = {0};
  sprintf(sessid_, "%d", sessid);

  printf("Running PPPoE-server\n");

  const char *pppoe_server = "/home/charlie/bt_digital_voice/RP_PPPOE_BT/src/pppoe-server";

  pid_t child;
  if ((child = fork()) == 0) {
   int execl_r = execl(pppoe_server, pppoe_server,"-N","1","-o",sessid_,"-L",li,"-R",ri,"-F","-I",ifname,(char*)NULL);
   if (execl_r < 0) {
    printf("execl(): %s\n",strerror(errno));
    exit(EXIT_FAILURE);
   }
  }

  int wstatus = 0;
  int fcount = 0;
  int ftotal = 0;
  while ((wait(&wstatus)) > 0);

  printf("pppoe-server died, listening for PADI packets\n");

  if (ioctl(sockfd, FIONREAD, &fcount)<0) {
   perror("ioctl():");
   exit(EXIT_FAILURE);
  }

  while (fcount) {
   nread = recvfrom(sockfd, buffer, RXBUFSIZ, 0, NULL, NULL);
   ftotal += nread;
   if (ioctl(sockfd, FIONREAD, &fcount)<0) {
    perror("ioctl():");
    exit(EXIT_FAILURE);
   }
  }

  printf("Flush check done, ftotal=%d\n",ftotal);
 }
}

