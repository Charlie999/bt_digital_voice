====

network structure

[ LAN ] <==> [ router ] <==> [ BT_PPPOE ] <==> [ ONT ]
  |                                ^
  |                                |
  |           /===> [ control ] ===/
  |           |
  |           V
  \===> [ RP_PPPOE_BT ] <==> [ BT hub ] <==> [ phone system ]

RP_PPPOE_BT & BT_PPPOE can be ran on the same machine.

The system allows the use of a "3rd party" router, without putting it in the SH2's DMZ.
(PPPoE access from router to ONT is transparent)

======[ BT_PPPOE    ]======

 - Spoofs Host_Uniq for Openreach
 - Gathers PADS session ID for the SH2

======[ RP_PPPOE_BT ]======

 - Supplies session ID to SH2

======[ control     ]======

 - Controls the above, gathers the Host_Uniq from SH2's PADI

Nothing's done yet.

/======================================================================\
| BT_PPPOE derived from https://github.com/gregnietsky/simpletun       |
| RP_PPPOE_BT derived from https://dianne.skoll.ca/projects/rp-pppoe/  |
\======================================================================/
