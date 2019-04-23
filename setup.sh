#!/bin/bash

echo "Allow the kernel to receive packet without opening a socket"

for port_num in {55555..55559}
do
  sudo iptables -t raw -A PREROUTING -p tcp --dport $port_num -j DROP
done
