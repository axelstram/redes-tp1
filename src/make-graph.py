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

#toma un diccionario de [ip1, ip2]
def crear_grafo(dicc):
	G = nx.DiGraph()

	for src in dicc.keys():
		for dst in dicc[src].keys():
			G.add_edge(src, dst)
	return G

# MAIN
if __name__ == '__main__':
	capture = []

	if len(sys.argv) > 1:
		capture = rdpcap(sys.argv[1])

		dicc = crear_dicc(capture)
		G = crear_grafo(dicc)

		# pos = nx.spring_layout(G)
		d = nx.degree(G)

		nx.draw_graph(G, 
			nodelist=d.keys(), 
			node_size=[v * 100 for v in d.values()], 
			node_shape='o',
			arrows=True,
			node_color='cyan', 
			font_size=10, 
			font_weight='bold', 
			style='solid',
			with_labels=False)
		
		outfile=sys.argv[1].split('/')[-1].split('.')[0] + ".eps"
		plt.savefig(outfile, format="EPS")