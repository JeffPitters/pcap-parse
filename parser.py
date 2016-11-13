#!/usr/bin/python2.7

import sys
import dpkt
max_fragments = 0.0
fragments_count = 0.0 
average_len_ip = 0.0
max_len_ip = 0.0
icmp_req_count = 0.0
icmp_rep_count = 0.0
icmp_req_freq = 0.0
icmp_rep_freq = 0.0
lost_icmp_count = 0.0
lost_icmp_freq = 0.0
arp_req_count = 0.0
arp_req_freq = 0.0
max_packet_freq = 0.0
min_packet_freq = 0.0
average_packet_freq = 0.0
is_incorrect_packet_proto = False
is_unusual_packet_proto = False

all_packet_count = 0.0
all_time_sec_count = 0.0
ip_packet_count = 0.0
cur_packet_freq = 0.0
cur_packet_count = 0.0
current_ts = 0.0

filename = sys.argv[1]
inputfile = open(filename)
pcap = dpkt.pcap.Reader(inputfile)

for ts, packet in pcap:
    if current_ts == 0:
        current_ts = ts;
    
    if (ts - current_ts) >= 10:
        all_time_sec_count += 1
        cur_packet_freq = cur_packet_count
        cur_packet_count = 0
        if cur_packet_freq > max_packet_freq:
            max_packet_freq = cur_packet_freq
        if cur_packet_freq < min_packet_freq:
            min_packet_freq = cur_packet_freq
        current_ts = ts
    
    all_packet_count += 1
    eth=dpkt.ethernet.Ethernet(packet) 
    ##ip packet
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip_packet_count += 1
        ip_pack = eth.data
        ##fragmentation check
        if ip_pack.off == dpkt.ip.IP_MF:
            source = ip_pack.src
            dest = ip_pack.dst
            if ip_pack.src == source and ip_pack.dst == dest and ip_pack.off == dpkt.ip.IP_MF:
                fragments_count += 1
            else:
                if fragments_count > max_fragments:
                    max_fragments = fragments_count
                fragments_count = 0
        ##packet len
        if ip_pack.len > max_len_ip:
            max_len_ip = ip_pack.len
        average_len_ip += ip_pack.len
        average_len_ip /= ip_packet_count
        ##proto is unusual
        if ip_pack.p > 143:
            is_incorrect_packet_proto = True
        if ip_pack.p !=0 and ip_pack.p != 1 and ip_pack.p != 4 and ip_pack.p != 6 and ip_pack.p != 17 and ip_pack.p != 58 and ip_pack.p != 59 and ip_pack.p != 60:
            is_unusual_packet_proto = True
        ##icmp
        if ip_pack.p == 1:
            icmp_pack = ip_pack.data
            if icmp_pack.type == dpkt.icmp.ICMP_ECHO:
                icmp_req_count += 1
            if icmp_pack.type == dpkt.icmp.ICMP_ECHOREPLY:
                icmp_rep_count += 1
            if icmp_pack.type == dpkt.icmp.ICMP_SRCQUENCH:
                lost_icmp_count +=1
    ##arp
    if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
        arp_pack = eth.data
        if arp_pack.op == dpkt.arp.ARP_OP_REQUEST or arp_pack.op == dpkt.arp.ARP_OP_REVREQUEST:
            arp_req_count += 1
print(all_time_sec_count)
print(ip_packet_count)
##average frequency and freqs of all packets
average_packet_freq = all_packet_count / all_time_sec_count
icmp_rep_freq = icmp_rep_count / all_time_sec_count 
icmp_req_freq = icmp_req_freq / all_time_sec_count
lost_icmp_freq = lost_icmp_count / all_time_sec_count
arp_req_freq = arp_req_count / all_time_sec_count

inputfile.close()
##write data in file
outfile = open(filename.replace('pcap','txt'), 'w')
outfile.write(str(max_fragments)+' '+str(average_len_ip)+' '+str(icmp_req_count)+' '+str(icmp_req_freq)+' '+str(icmp_rep_count)+' '+str(icmp_rep_freq)+' '+str(lost_icmp_count)+' '+str(lost_icmp_freq)+' '+str(arp_req_count)+' '+str(arp_req_freq)+' '+str(max_packet_freq)+' '+str(min_packet_freq)+' '+str(average_packet_freq)+' '+str(is_incorrect_packet_proto)+' '+str(is_unusual_packet_proto))
outfile.close()

    
