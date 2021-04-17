import matplotlib.pyplot as plt
import pandas as pd
import numpy as np


def bin2dec(b):
    d = 0
    for i, x in enumerate(b):
        d += 2 ** (-i - 1) * x
    return d


def dec2bin(x):
    x -= int(x)
    bins = []
    while x:
        x *= 2
        bins.append(1 if x >= 1. else 0)
        x -= int(x)
    return bins


def dec2bin2(x):
    base = [0, 1]
    mid = []
    while True:
        if x == 0: break
        x, rem = divmod(x, 2)
        mid.append(base[rem])
    mid.reverse()
    return mid


def data_convert(data):
    int_part = data >> 4
    dec_part = data & 0xf
    t1 = dec2bin2(dec_part)
    dec_result = bin2dec(t1)
    result = int_part + dec_result
    return result

p4_entropy = pd.read_csv("../result/p4_estimate_entropy.csv",header=None,names=['en_p4'])
real_entropy = pd.read_csv("../result/real_entropy.csv")
#compare algorithm. https://github.com/aclapolli/ddosd-p4/blob/master/README.md
ec_entropy = pd.read_csv("../result/ddosd-result.csv",header=None,names=['t','en_ec'])

print p4_entropy
print real_entropy
print ec_entropy

p4_entropy_dec = [] #the last 4 bit store as decimals. so we need convert it
for i in range(len(p4_entropy.en_p4)):
    t = data_convert(p4_entropy.en_p4[i])
    p4_entropy_dec.append(t)

ec_entropy_dec = []
for i in range(len(ec_entropy)):
    t = data_convert(ec_entropy.en_ec[i])
    ec_entropy_dec.append(t)

x_FL = p4_entropy_dec
x_EC = ec_entropy_dec
x_Real = real_entropy.entropy

error1 = [x_FL[i] - x_Real[i] for i in range(0,len(x_FL))]
error1_abs = np.absolute(error1)
error2 = [x_EC[i] - x_Real[i] for i in range(0,len(x_EC))]
error2_abs = np.absolute(error2)
print np.mean(error1_abs)
print np.mean(error2_abs)
#print len(p4_entropy_dec)
x= list(range(1,16))
l1, = plt.plot(x,p4_entropy_dec)
l2, = plt.plot(x,ec_entropy_dec)
l3, = plt.plot(x,real_entropy.entropy)

plt.legend(handles=[l1,l2,l3],labels=['Filter-Sketch','Euclid','Real Entropy'],loc='best');
plt.xlabel('Observation Windows')
plt.ylabel('entropy value')
plt.show();



