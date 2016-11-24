from __future__ import division
from scapy.all import *
import numpy as np
import sys
import networkx as nx

broadcast_counter = 0
total_packets = 0
nodos_distinguidos = {}

def arp_monitor_callback(pkt):
	global total_packets
	global broadcast_counter
	global nodos_distinguidos 

	#total_packets += 1
	if ARP in pkt and pkt[ARP].op == whoHasORisAt: #who-has or is-at
		# Lo pase adentro porque no vamos a tener en cuenta sobre el total los paquetes de otros tipos para calcular Entropia
		total_packets += 1

		if hostORdest == 1:			
			if pkt.getlayer(ARP).psrc in nodos_distinguidos.keys():
				nodos_distinguidos[pkt.getlayer(ARP).psrc] +=1
			else:
				nodos_distinguidos[pkt.getlayer(ARP).psrc] = 1
		else:
			if pkt.getlayer(ARP).pdst in nodos_distinguidos.keys():
				nodos_distinguidos[pkt.getlayer(ARP).pdst] +=1
			else:
				nodos_distinguidos[pkt.getlayer(ARP).pdst] = 1

		# print "broadcast: ", broadcast_counter / total_packets
		 
		# for i in nodos_distinguidos.keys():
		# 	print i, ": ", nodos_distinguidos[i] / total_packets


#toma un diccionario de [ip, #repeticiones] (por ahi hay que cambiarlo a [ip, probabilidad])
def entropy(dicc):
    l = []
    N = float(sum(dicc.values()))
    P = [i/N for i in dicc.values()]
	# genera una lista de tuplas (informacion, ip) para poderla ordenar y devolverla
    j = 0
    for i,k in dicc.iteritems():
	l.append((-np.log2(P[j]), i))
	j +=1
	
    l.sort()

    #I = [-np.log2(p) for p in P]
    H = sum([p*(-np.log2(p)) for p in P])

    return [H, l]


#toma un diccionario de [ip1, ip2]
def crear_grafo(dicc):
	G = nx.Graph()

	for key, value in dicc.iteritems():
		G.add_edge(key, value)
	
	return G	

# GLOBAL VARIABLES
whoHasORisAt = 1
hostORdest = 1

#Si le paso un argumento, asumo que es una captura en formato libpcap. Sino, sniffeo la red
if __name__ == '__main__':
	capture = []

	# who-has or is-at
	whoHasORisAt= int(raw_input("Who-Has (1) or Is-At(2)?: "))
	# host or dest
	hostORdest= int(raw_input("Host (1) or Dest(2)?: "))

	if len(sys.argv) > 1:
		capture = rdpcap(sys.argv[1])

		for pkt in capture:
			arp_monitor_callback(pkt)

		# Al pedo
		# print nodos_distinguidos
		[e, i] = entropy(nodos_distinguidos)
		print "entropy " 
		print e
		# Imprime los 5 con menos informacion
		print "information "
		print i[0:5]
		# Imprime el que tiene mas informacion para comparar porcentajes
		print i[len(i)-1]
			
	else:
		sniff(prn = arp_monitor_callback, filter = "arp", store = 0)

