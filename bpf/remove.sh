#!/bin/bash

I1=enp2s0
I2=enp3s0

function app() {
 tc qdisc del dev $1 clsact

 echo -e "Removed BPF from $1\n==="

 tc filter show dev $1 ingress
 tc filter show dev $1 egress

 echo "==="

}

app $I1
app $I2
