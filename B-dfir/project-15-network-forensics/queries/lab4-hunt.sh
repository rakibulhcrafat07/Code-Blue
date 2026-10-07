#!/bin/bash
# Lab 4 hunting commands (tshark)
P=${1:-malware.pcap}
tshark -r "$P" -Y 'dns.flags.response==0' -T fields -e frame.time -e dns.qry.name | sort -u
tshark -r "$P" -Y http.request -T fields -e frame.time -e ip.dst -e http.host -e http.request.uri -e http.user_agent
tshark -r "$P" -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e frame.time_epoch -e ip.dst
mkdir -p exported && tshark -r "$P" --export-objects http,./exported
