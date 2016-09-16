from __future__ import division
from scapy.all import *
import numpy as np
import sys


#toma un diccionario de [ip, #repeticiones]
def entropy(dicc):
    N = float(sum(dicc.values()))
    P = [i/N for i in dicc.values()]
    H = -sum([p*numpy.log2(p) for p in P])

    return H

