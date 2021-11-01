#ifndef PPPOE_H
#define PPPOE_H

typedef struct padhdr {
 unsigned char vertype;
 unsigned char code;
 unsigned short sessid;
 unsigned short len;
} __attribute__((packed));

#endif
