from __future__ import division
from scapy.all import *
import numpy as np
import sys

broadcast_counter = 0
total_packets = 0
host_dict = {}

def arp_monitor_callback(pkt):
	global total_packets
	global broadcast_counter
	global host_dict 
	
	
	if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
		total_packets += 1

		if pkt.dst == "ff:ff:ff:ff:ff:ff":
			broadcast_counter += 1
		else:
			#print pkt.getlayer(ARP).pdst
			if pkt.getlayer(ARP).pdst in host_dict.keys():
				host_dict[pkt.getlayer(ARP).pdst] +=1
			else:
				host_dict[pkt.getlayer(ARP).pdst] = 1

		print "broadcast: ", broadcast_counter / total_packets 
		for i in host_dict.keys():
			print i, ": ", host_dict[i] / total_packets
	


#Si le paso un argumento, asumo que es una captura en formato libpcap. Sino, sniffeo la red
if __name__ == '__main__':
	capture = []

	if len(sys.argv) > 1:
		capture = rdpcap(sys.argv[1])

		for pkt in capture:
			arp_monitor_callback(pkt)
			
	else:
		sniff(prn = arp_monitor_callback, filter = "arp", store = 0)
