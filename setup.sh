#!/bin/bash

if [ $# -lt 1 ]
then
  echo "You need to specify number of ports you want to open from 55555"
  exit 1
fi

echo "Allow the kernel to receive packet without opening a socket"

for port_num in $(seq 55555 $((55554 + $1)))
do

  echo sudo iptables -t raw -A PREROUTING -p tcp --dport $port_num -j DROP
  sudo iptables -t raw -A PREROUTING -p tcp --dport $port_num -j DROP
done
