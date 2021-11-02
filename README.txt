====

network structure

[ LAN ] <==> [ router ] <==> [ BT_PPPOE ] <==> [ ONT ]
  |
  |
  \===> [ RP_PPPOE_BT ] <==> [ BT hub ] <==> [ phone system ]

RP_PPPOE_BT & BT_PPPOE can be ran on the same machine.

The system allows the use of a "3rd party" router, without putting it in the HH2's DMZ.

======[ BT_PPPOE    ]======

 - Spoofs Host_Uniq for Openreach
 - Gathers PADS session ID for the HH2


======[ RP_PPPOE_BT ]======

 - Supplies session ID to HH2
 - Gathers Host_Uniq for Openreach


Nothing's done yet.

/======================================================================\
| BT_PPPOE derived from https://github.com/gregnietsky/simpletun       |
| RP_PPPOE_BT derived from https://dianne.skoll.ca/projects/rp-pppoe/  |
\======================================================================/
