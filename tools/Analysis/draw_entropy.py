import matplotlib.pyplot as plt
import pandas as pd


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
print p4_entropy
print real_entropy


p4_entropy_dec = [] #the last 4 bit store as decimals. so we need convert it
for i in range(len(p4_entropy.en_p4)):
    t = data_convert(p4_entropy.en_p4[i])
    p4_entropy_dec.append(t)

print p4_entropy_dec




x= list(range(1,16))
plt.plot(x,p4_entropy_dec)
plt.plot(x,real_entropy.entropy)
plt.show();



