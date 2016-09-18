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

    for ip in data.keys():
    	cantRepeticiones = data[ip]
    	ipInf[ip] = -np.log2(cantRepeticiones/N)
   	
    return ipInf
   

def generar_data_dicc(capture):
	data = {}
	

	return data

#parametros: captura, titulo
if __name__ == '__main__':
	capture = rdpcap(sys.argv[1])
	titulo = sys.argv[2]
	data = generar_data_dicc(capture)
	#data = {'192.168.0.1':10, '192.168.0.2':25, '192.168.0.3':13, '192.168.0.4':17, '192.168.0.5':10} #(ip, cant de veces que aparece)
	informacion = calcular_informacion(data)
	entropia = calcular_entropia(data)
	graficar_informacion_y_entropia(informacion, entropia, titulo="")
