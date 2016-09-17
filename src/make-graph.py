from __future__ import division
from scapy.all import *
import matplotlib.pyplot as plt
import sys
import networkx as nx


def crear_dicc(capture, filter_broadcast):
	connections = {} #dic{src: {dst: cant veces} }

	for pkt in capture:
		if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
			if filter_broadcast and pkt.dst != "ff:ff:ff:ff:ff:ff":
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
	G = nx.Graph()

	for src in dicc.keys():
		for dst in dicc[src].keys():
			G.add_edge(src, dst)
	return G

# MAIN
if __name__ == '__main__':
	capture = []

	if len(sys.argv) > 1:
		capture = rdpcap(sys.argv[1])

		filter_broadcast_option = raw_input('wacho, filtro los filter_broadcast (y) o no (n <- default)?: ')
		filter_broadcast = False
		if 'y' in filter_broadcast_option:
			filter_broadcast = True

		dicc = crear_dicc(capture, filter_broadcast)
		G = crear_grafo(dicc)

		pos = nx.spring_layout(G)

		#https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.drawing.nx_pylab.draw_networkx.html#networkx.drawing.nx_pylab.draw_networkx
		nx.draw(G, pos, 
			node_size=1000, 
			node_shape='o', # tratamos de meterle un rectangulo pero no hubo caso --> http://matplotlib.org/api/markers_api.html
			node_color='cyan', 
			font_size=10, 
			font_weight='bold', 
			style='solid',
			with_labels=True)
		
		
		outfile=sys.argv[1].split('/')[-1].split('.')[0] + ".eps"
		#plt.savefig("Graph.png", format="PNG")
		plt.savefig(outfile, format="EPS")
