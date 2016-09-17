from __future__ import division
from scapy.all import *
import matplotlib.pyplot as plt
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
	return src_dst

#toma un diccionario de [ip1, ip2]
def crear_grafo(dicc):
	G = nx.Graph()

	for key, value in dicc.iteritems():
		G.add_edge(key, value)
	return G

if __name__ == '__main__':
	capture = []

	if len(sys.argv) > 1:
		capture = rdpcap(sys.argv[1])

		dicc = crear_dicc(capture)
		#dicc = {'10.245.86.122': '10.245.85.143', '10.245.84.54': '10.245.85.143', '10.245.80.1': '10.245.85.143', '10.245.87.23': '10.245.85.143', '192.168.43.218': '192.168.43.1', '10.245.83.6': '10.245.85.143', '192.168.43.1': '192.168.43.218', '10.245.85.143': '10.245.80.3', '10.245.80.3': '10.245.85.143', '10.245.80.2': '10.245.85.143'}
		
		G = crear_grafo(dicc)

		pos = nx.spring_layout(G)

		#https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.drawing.nx_pylab.draw_networkx.html#networkx.drawing.nx_pylab.draw_networkx
		nx.draw(G, pos, 
			node_size=6000, 
			node_shape='_', # tratamos de meterle un rectangulo pero no hubo caso --> http://matplotlib.org/api/markers_api.html
			node_color='cyan', 
			font_size=10, 
			font_weight='bold', 
			style='solid',
			with_labels=True)
		
		
		outfile=sys.argv[1].split('/')[-1].split('.')[0] + ".eps"
		#plt.savefig("Graph.png", format="PNG")
		plt.savefig(outfile, format="EPS")
