from __future__ import division
from scapy.all import *
import numpy as np
import sys
import networkx as nx
from netaddr import *

broadcast_counter = 0
total_packets = 0
nodos = {}

connections = {} #dic{src: [dst] } o #dic{dst: [src] } depende el modo que se elija

def arp_monitor_callback(pkt):
	global total_packets
	global broadcast_counter
	global nodos 

	if ARP in pkt and pkt[ARP].op == whoHasORisAt: #who-has or is-at
		total_packets += 1

		if hostORdest == 1:
			agregarADiccNodos(pkt.getlayer(ARP).psrc)
			agregarADiccConnections(pkt.getlayer(ARP).psrc, pkt.getlayer(ARP).pdst)
		else:
			agregarADiccNodos(pkt.getlayer(ARP).pdst)
			agregarADiccConnections(pkt.getlayer(ARP).pdst, pkt.getlayer(ARP).psrc)

		# print "broadcast: ", broadcast_counter / total_packets
		 
		# for i in nodos.keys():
		# 	print i, ": ", nodos[i] / total_packets

def agregarADiccNodos(host):
	if host in nodos.keys():
		nodos[host] +=1
	else:
		nodos[host] = 1

def agregarADiccConnections(host, host_connection):
	if host in connections.keys():
		nodos[host].append(host_connection)
	else:
		nodos[host] = [host_connection]

def groupConnectionsByNetwork(host_connections):
	#ToDo

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
		# print nodos
		[e, i] = entropy(nodos)
		print "entropy " 
		print e
		# Imprime los 5 con menos informacion
		print "information "
		print i[0:5]
		# Imprime el que tiene mas informacion para comparar porcentajes
		print i[len(i)-1]


		dist = []
		non_dist = []
		for nodo in i:
			if nodo[0] < e:
				dist.append(nodo)
			else:
				non_dist.append(nodo)
		print "Distinguidos"
		print dist
		# Crea una lista de IPaddress de non_dist
		ip_addr = [IPAddress(i) for i in [seq[1] for seq in non_dist]]

		#merged = cidr_merge(ip_addr)
		#print "Nodos no distinguidos sumarizados"
		#print merged

		# Para generar las /24
		# cidr = IPNetwork('.'.join(str(ip).split('.')[0:3]) + '.0/24')


		#dicc {red}: #veces que se conecta <--
		#[hosts] ---> [redes] 


		for host, host_connections in connections.iteritems():
			if host in dist: #si el host es distinguido
				#modificar las conecciones a host por conecciones a redes
				connections[host] = groupConnectionsByNetwork(host_connections)
			else:
				#eliminar la clave del diccionario
				connections.pop(host, None)
		
			
	else:
		sniff(prn = arp_monitor_callback, filter = "arp", store = 0)

