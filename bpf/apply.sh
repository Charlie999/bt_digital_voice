#!/bin/bash

if [ $# -ne 2 ]; then
	echo "usage: ./apply.sh <if> <mode>"
	exit 1
fi

WD="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

function ont() {
 tc qdisc del dev $1 clsact

 tc qdisc add dev $1 clsact
 tc filter add dev $1 ingress bpf da obj $WD/bt_bpf.o sec bt_pppoe_ingress
 tc filter add dev $1 egress bpf da obj $WD/bt_bpf.o sec bt_pppoe_egress

 tc filter add dev $1 egress bpf da obj $WD/bt_ont_bpf.o sec bt_pppoe_ont_egress

 echo -e "Added BPF to $1\n==="

 tc filter show dev $1 ingress
 tc filter show dev $1 egress

 echo "==="

}

function rt() {
 tc qdisc del dev $1 clsact

 tc qdisc add dev $1 clsact
 tc filter add dev $1 ingress bpf da obj $WD/bt_bpf.o sec bt_pppoe_ingress
 tc filter add dev $1 egress bpf da obj $WD/bt_bpf.o sec bt_pppoe_egress

 tc filter add dev $1 egress bpf da obj $WD/bt_rt_bpf.o sec bt_pppoe_rt_egress

 echo -e "Added BPF to $1\n==="

 tc filter show dev $1 ingress
 tc filter show dev $1 egress

 echo "==="

}

$2 $1
