#!/bin/bash

I1=enp2s0
I2=enp3s0

function ont() {
 tc qdisc del dev $1 clsact

 tc qdisc add dev $1 clsact
 tc filter add dev $1 ingress bpf da obj bt_bpf.o sec bt_pppoe_ingress
 tc filter add dev $1 egress bpf da obj bt_bpf.o sec bt_pppoe_egress

 tc filter add dev $1 egress bpf da obj bt_ont_bpf.o sec bt_pppoe_ont_egress

 echo -e "Added BPF to $1\n==="

 tc filter show dev $1 ingress
 tc filter show dev $1 egress

 echo "==="

}

function rt() {
 tc qdisc del dev $1 clsact

 tc qdisc add dev $1 clsact
 tc filter add dev $1 ingress bpf da obj bt_bpf.o sec bt_pppoe_ingress
 tc filter add dev $1 egress bpf da obj bt_bpf.o sec bt_pppoe_egress

 tc filter add dev $1 egress bpf da obj bt_rt_bpf.o sec bt_pppoe_rt_egress

 echo -e "Added BPF to $1\n==="

 tc filter show dev $1 ingress
 tc filter show dev $1 egress

 echo "==="

}

ont $I1
rt $I2
