from __future__ import division
from scapy.all import *
import numpy as np
import sys
import networkx as nx


def crear_dicc(capture):
	src_dst = {}

	for pkt in capture:
		if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
			if pkt.dst != "ff:ff:ff:ff:ff:ff":
				pkt_dst = pkt.getlayer(ARP).pdst
				pkt_src = pkt.getlayer(ARP).psrc

				src_dst[pkt_src] = pkt_dst
	print src_dst
	return src_dst

#toma un diccionario de [ip1, ip2]
def crear_grafo(dicc):
	G = nx.Graph()

	for key, value in dicc.iteritems():
		G.add_edge(key, value)
	
	print G
	return G

if __name__ == '__main__':
	capture = []

	if len(sys.argv) > 1:
		capture = rdpcap(sys.argv[1])

		# dicc = crear_dicc(capture)
		dicc = {'10.245.86.122': '10.245.85.143', '10.245.84.54': '10.245.85.143', '10.245.80.1': '10.245.85.143', '10.245.87.23': '10.245.85.143', '192.168.43.218': '192.168.43.1', '10.245.83.6': '10.245.85.143', '192.168.43.1': '192.168.43.218', '10.245.85.143': '10.245.80.3', '10.245.80.3': '10.245.85.143', '10.245.80.2': '10.245.85.143'}
		
		crear_grafo(dicc)
