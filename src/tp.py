from __future__ import division
from scapy.all import *
import numpy as np
import sys

broadcast_counter = 0
total_packets = 0

def arp_monitor_callback(pkt):
	total_packets += 1

	if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
		if pkt.dst == "ff:ff:ff:ff:ff:ff":
			broadcast_counter += 1

	print "broadcast: ", broadcast_counter / total_packets, " unicast: ", (total_packets - broadcast_counter) / total_packets
	


#Si le paso un argumento, asumo que es una captura en formato libpcap. Sino, sniffeo la red
if __name__ == '__main__':
	capture = []

	if len(sys.argv) > 1:
		capture = rdpcap(sys.argv[1])
	else:
		sniff(prn = arp_monitor_callback, filter = "arp", store = 0)

	
