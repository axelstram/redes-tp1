from __future__ import division
from scapy.all import *
import matplotlib.pyplot as plt
import sys
import networkx as nx


def crear_dicc(capture):
	connections = {} #dic{src: {dst: cant veces} }

	for pkt in capture:
		if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
				pkt_src = pkt.getlayer(ARP).psrc
				pkt_dst = pkt.getlayer(ARP).pdst

				if pkt_src in connections.keys():
					if pkt_dst in connections[pkt_src].keys():
						connections[pkt_src][pkt_dst] += 1
					else:
						connections[pkt_src][pkt_dst] = 1
				else:
					connections[pkt_src] = {pkt_dst: 1}
	return connections

# MAIN
if __name__ == '__main__':
	capture = []

	if len(sys.argv) > 1:
		capture = rdpcap(sys.argv[1])

		dicc = crear_dicc(capture)

		outfile=sys.argv[1].split('/')[-1].split('.')[0] + ".eps"

		f = file('dot/{0}.dot'.format(outfile), 'w')

		f.write('digraph G {\n')

		for src in dicc.keys():
			for dst in dicc[src].keys():
				edge = '	"{0}"->"{1}" [color="#1E1EA8"];\n'.format(src, dst)
				f.write(edge)

		f.write('}')

