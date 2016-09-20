from __future__ import division
from scapy.all import *
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import sys
import operator

#informacion = dicc(ip, informacion)
#entropia = float
#titulo = titulo papurro
def graficar_informacion_y_entropia(informacion, entropia, titulo):
	sorted_data = sorted(informacion.items(), key=operator.itemgetter(1)) #sort por value
	ips = []
	informacion = []

	for tupla in sorted_data:
		ips.append(tupla[0])
		informacion.append(tupla[1])


	plt.xlabel('Direcciones IP')
	plt.ylabel('Informacion')
	plt.ylim([0, informacion[len(informacion)-1] + 5])
	plt.tight_layout()

	#grafico informacion
	plt.bar(range(len(informacion)), informacion, align='center')
	plt.xticks(range(len(ips)), ips)

	#grafico entropia
	entropia_maxima = np.log2(len(informacion))
	
	red_patch = mpatches.Patch(color='red', label='Entropia real')
	green_patch = mpatches.Patch(color='green', label='Entropia maxima')
	plt.legend(handles=[red_patch, green_patch])
	plt.plot([-1] + range(len(informacion)) + [len(informacion)], [entropia]*(len(informacion)+2), linewidth=3.0, color='red')	 
	plt.plot([-1] + range(len(informacion)) + [len(informacion)], [entropia_maxima]*(len(informacion)+2), linewidth=3.0, color='green')	 

	plt.show()
	plt.savefig(titulo) 



#data = dicc(ip, #repeticiones)
def calcular_entropia(data):
    N = float(sum(data.values()))
    P = [i/N for i in data.values()]
    H = sum([p*(-np.log2(p)) for p in P])

    return H



#data = dicc(ip, #repeticiones)
def calcular_informacion(data):
	N = float(sum(data.values()))
	ipInf = {}
    	
	for ip, cantRepeticiones in data.items():
		ipInf[str(ip)] = -np.log2(cantRepeticiones/N)

	#print ipInf
	#me quedo con los 10 de menor informacion (para poder encontrar el gateway)
	ipInf_sorted_list = sorted(ipInf.items(), key=lambda x:x[1]) #sort por value
	ipInf_sorted_dicc = {}
	
	#print ipInf_sorted_list
	i = 0
	for t in ipInf_sorted_list:
		if i < min(10, len(ipInf_sorted_list)):
			ipInf_sorted_dicc[str(t[0])] = t[1]
		else:
			break

		i += 1

	#print ipInf_sorted_dicc

	return ipInf_sorted_dicc
   


#toma un capture y devuelve un dicc(ip, cant de veces que aparece como src)
def generar_data_dicc(capture):
	data = {}
	
	for pkt in capture:
		if ARP in pkt and pkt[ARP].op == 1: #who-has
			if pkt[ARP].psrc in data.keys():
				data[pkt[ARP].psrc] += 1
			else:
				data[pkt[ARP].psrc] = 1

	return data




#parametros: captura, titulo
if __name__ == '__main__':
	capture = rdpcap(sys.argv[1])
	titulo = sys.argv[2]
	
	data = generar_data_dicc(capture)
	informacion = calcular_informacion(data)
	entropia = calcular_entropia(data)
	graficar_informacion_y_entropia(informacion, entropia, titulo="")