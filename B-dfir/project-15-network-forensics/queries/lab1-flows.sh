#!/bin/bash
# Lab 1: use the nfdump 1.5.8 binary built from source, and the Argus client 'ra'
NF=./src/nfdump/nfdump
$NF -R cisco-asa-nfcapd -s srcip/bytes -n 10
$NF -R cisco-asa-nfcapd -s dstport/flows -n 10
$NF -R cisco-asa-nfcapd 'dst port 22' -A srcip
ra -r argus-collector.ra -s stime saddr daddr dport pkts bytes - 'tcp and dst port 22'
