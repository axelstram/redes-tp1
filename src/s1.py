from __future__ import division
from scapy.all import *
import numpy as np
import sys
import networkx as nx
import matplotlib.pyplot as plt
from netaddr import *


# GLOBAL VARIABLES
tipoDePaqueteARP = 1
distingoPorSource = True
broadcast_counter = 0
total_packets = 0
nodos = {} #{host: cant de apariciones}
connections = {} #{src: [dst] } o {dst: [src] } depende el modo que se elija

def arp_monitor_callback(pkt):
	global total_packets
	global broadcast_counter
	global nodos 

	if ARP in pkt and pkt[ARP].op == tipoDePaqueteARP: #who-has or is-at
		total_packets += 1

		if distingoPorSource:
			agregarADiccNodos(pkt.getlayer(ARP).psrc)
			agregarADiccConnections(pkt.getlayer(ARP).psrc, pkt.getlayer(ARP).pdst)
		else:
			agregarADiccNodos(pkt.getlayer(ARP).pdst)
			agregarADiccConnections(pkt.getlayer(ARP).pdst, pkt.getlayer(ARP).psrc)


def agregarADiccNodos(host):
	if host in nodos.keys():
		nodos[host] += 1
	else:
		nodos[host] = 1


def agregarADiccConnections(host, host_connection):
	if host in connections.keys():
		connections[host].append(host_connection)
	else:
		connections[host] = [host_connection]


def crearGrafo(node_information, network_sizes, nodes_connections):
	G = nx.DiGraph()

	for nodo in nodes_connections.keys():
		for conection in nodes_connections[nodo]:
			G.add_edge(nodo, conection)

	max_network_size = 0
	if network_sizes: 
		max_network_size = max(network_sizes.values())
	degrees = nx.degree(G)
	colors = []
	sizes = []

	#color: si es distinguido verde sino azul
	#size: si es distinguido depende de su informacion, caso contrario de su grado o el tamanio de la red
	for n in G.nodes():
		if n in node_information.keys():
			colors.append('#61c94a')
			sizes.append(1500/node_information[n])
		else:
			colors.append('#718af7')
			if n in network_sizes.keys():
				size = (network_sizes[n]/max_network_size) * 1000
				if size<100:
					size=100
				sizes.append(size)
			else:
				sizes.append(degrees[n] * 100)


	nx.draw_networkx(G,
		node_size=sizes, 
		node_color=colors, 
		node_shape='o',
		edge_color='#9b9b9b',
		arrows=True,
		font_size=12, 
		font_weight='bold',
		font_color='black', 
		style='solid',
		with_labels=True)
	
	if len(sys.argv) > 1:
		outfile=sys.argv[1].split('/')[-1].split('.')[0] + ".eps"
	else:
		outfile=raw_input("Ingrese un nombre para el grafico (sin extension): ")
		outfile+=".eps"
	
	plt.savefig(outfile, format="EPS")
	plt.show()

#agrupa las conecciones con nodos no distinguidos en redes
def groupConnectionsByNetwork(redes, nodos_distinguidos, host_connections):
	networks_connections = set()
	
	for host in host_connections:
		ip = IPAddress(host)
		if ip in nodos_distinguidos:
			networks_connections.add(ip)
		else:
			for red, veces in redes.iteritems():
				if ip in red:
					networks_connections.add(red)
					break

	return list(networks_connections)


#toma un diccionario de [ip, #repeticiones] (por ahi hay que cambiarlo a [ip, probabilidad])
def entropy(nodos):
	informacionPorNodo = []
	N = float(sum(nodos.values())) #N= cantidad total de paquetes 'interesantes'

	probabilidad = {} # {host: probabilidad}

	for host, apariciones in nodos.iteritems():
		probabilidad[host] = apariciones/N
		informacion = -np.log2(probabilidad[host])
		informacionPorNodo.append((host, informacion))
	
	# Sort en base al segundo parametro
	informacionPorNodo.sort(key=lambda n: n[1]) 

	# H = entropia = suma de informaciones (informacion = -log2(probabilidad))
	H = sum([p*(-np.log2(p)) for host, p in probabilidad.iteritems()])

	return [H, informacionPorNodo]



# Funcion para generar un diccionario de redes sumarizadas con cantidad de nodos que la componen
def sumarizar_redes(no_distinguidos):
	ip_addr = [IPAddress(i) for i in [seq[0] for seq in no_distinguidos]]

	redes = {}
	for ip in ip_addr:
		cidr = IPNetwork('.'.join(str(ip).split('.')[0:3]) + '.0/24')
		if cidr not in redes.keys():
			redes[cidr] = 1
		else:
			redes[cidr] += 1
	#print redes
	# Para sumarizar
	redes_l = []
	nodos_cant_l = []
	for r, s in redes.iteritems():
		redes_l.append(r)
		nodos_cant_l.append(s)
	redes_sum = cidr_merge(redes_l)
	#print "Redes Sumarizadas"
	#print redes_sum
	# Para generar el diccionario con cantidad de hosts por sumarizada
	redes_sumarizadas = {}
	for r in redes_l:
		for sn in redes_sum:
			if r in sn:
				if sn not in redes_sumarizadas:
					redes_sumarizadas[sn] = nodos_cant_l[redes_l.index(r)]
				else:
					redes_sumarizadas[sn] += nodos_cant_l[redes_l.index(r)]
	return redes_sumarizadas

def dividir_nodos(entropia, informacionPorNodo):
	# Listas de distinguidos vs no distinguidos

	distinguidos = []
	no_distinguidos = []
	for nodo in informacionPorNodo: #informacionPorNodo = [(ip, probabilidad)]
		if nodo[1] < entropia:
			distinguidos.append(nodo)
		else:
			no_distinguidos.append(nodo)

	return [distinguidos, no_distinguidos]

				
#Si le paso un argumento, asumo que es una captura en formato libpcap. Sino, sniffeo la red
if __name__ == '__main__':
	capture = []

	# who-has or is-at
	tipoDePaqueteARP = int(raw_input("Who-Has (1) or Is-At(2)?: "))
	# source or dest
	opcion = int(raw_input("Source (1) or Dest(2)?: "))

	if opcion == 1:
		distingoPorSource = True
	else: 
		distingoPorSource = False

	print "...................................................."

	if len(sys.argv) > 1:
		print "Analizando captura"
		capture = rdpcap(sys.argv[1])

		for pkt in capture:
			arp_monitor_callback(pkt)
	else:
		print "Capturando trafico..."
		sniff(prn = arp_monitor_callback, filter = "arp", store = 0)

	print "...................................................."

	# ENTROPIA
	[entropia, informacionPorNodo] = entropy(nodos)
	print "La entropia de la fuente es: "
	print entropia
	print "...................................................."

	# DISTINCION DE NODOS
	[distinguidos, no_distinguidos] = dividir_nodos(entropia, informacionPorNodo)
	
	resp = raw_input("Imprimir informacion de cada nodo distinguido? (s o n): ")
	if 's' in resp:
		print "Nodos distinguidos: ", distinguidos
	else:
		print "Nodos distinguidos: ", [n[0] for n in distinguidos]

	resp = raw_input("Imprimir nodos NO distinguidos? (s o n): ")
	if 's' in resp:
		resp = raw_input("Y la informacion de cada nodo NO distinguido? (s o n): ")
		if 's' in resp:
			print "Nodos NO distinguidos: ", no_distinguidos
		else:
			print "Nodos NO distinguidos: ", [n[0] for n in no_distinguidos]
	print "...................................................."

	# SUMARIZAR POR REDES LOS NO DISTINGUIDOS
	redes = {}
	sumarize = raw_input("Sumarizar redes en los nodos no distinguidos? (s o n): ")
	if 's' in sumarize:
		redes = sumarizar_redes(no_distinguidos)
		print "Redes con cantidad de hits: ", redes
	print "...................................................."

	withNoDistConnections = raw_input("Agregar las conecciones de los nodos no distinguidos? (s o n): ")

	print "Creando diccionario de nodos y sus conecciones: "
	nodes_connections = {}
	nodes = []

	if 's' in withNoDistConnections:
		nodes = connections.keys()
	else:
		nodes = [d[0] for d in distinguidos]

	for host, host_connections in connections.iteritems():
		if host in nodes:
			if 's' in sumarize:
				nodes_connections[host] = groupConnectionsByNetwork(redes, nodes, host_connections)
			else:
				nodes_connections[host] = list(set(host_connections))

	print nodes_connections
	
	print "...................................................."
	
	print "Creando grafo de la red..."
	crearGrafo(dict(distinguidos), redes, nodes_connections)



