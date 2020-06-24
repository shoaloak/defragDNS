#!/bin/bash
# log ICMP message to detect path MTU

#LOG="/var/log/traffic/icmp-traffic.pcap.%Y%m%d-%H"
LOG="traffic/icmp-traffic.pcap.%Y%m%d-%H"

trap "" 1
tcpdump -n -i eth0 -s 0 -w $LOG -G 3600 icmp or icmp6
