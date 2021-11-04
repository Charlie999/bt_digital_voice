#ifndef CONTROL_H
#define CONTROL_H

#define CTRL_CD_GET  0x1000
#define CTRL_CD_SET  0x2000
#define CTRL_CD_SEND 0x3000
#define CTRL_CD_RESP 0x4000
#define CTRL_CD_EVNT 0x5000

#define CTRL_SET_HOSTUNIQ       CTRL_CD_SET  + 0
#define CTRL_GET_HOSTUNIQ       CTRL_CD_GET  + 0
#define CTRL_RESP_HOSTUNIQ      CTRL_CD_RESP + 0

#define CTRL_GET_SESSID         CTRL_CD_GET  + 1
#define CTRL_RESP_SESSID        CTRL_CD_RESP + 1

#define CTRL_SEND_PADT          CTRL_CD_SEND + 2

#define CTRL_GET_LASTHOSTUNIQ   CTRL_CD_GET  + 3
#define CTRL_RESP_LASTHOSTUNIQ  CTRL_CD_RESP + 3

#define CTRL_EVENT_SESSIONID    CTRL_CD_EVNT + 4

typedef struct ctrlmsg {
 unsigned long magic;
 unsigned short type;
 unsigned short dlen;
 unsigned char data[32];
} __attribute__((packed));

#endif
