====

network structure

[ LAN ] <==> [ router ] <==> [ BT_PPPOE ] <==> [ ONT ]
  |
  |
  \===> [ RP_PPPOE_BT ] <==> [ BT hub ] <==> [ phone system ]

RP_PPPOE_BT & BT_PPPOE can be ran on the same machine.


======[ BT_PPPOE    ]======

 - Spoofs Host_Uniq for Openreach
 - Gathers PADS session ID for the HH2


======[ RP_PPPOE_BT ]======

 - Supplies session ID to HH2
 - Gathers Host_Uniq for Openreach
 - Soon:tm:


Nothing's done yet.
