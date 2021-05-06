from scipy import stats
import pandas as pd
import scapy.all as scapy
from scapy.all import *
import numpy as np
import math

def Get_IP(pcap_file):
    packets = rdpcap(pcap_file)
    ips=[]
    for pkt in packets:
#        print pkt[IP].fields['src']
        if pkt.haslayer(IP) == 1:
            print pkt[IP].fields['src']
            ips.append(pkt[IP].fields['src'])
    #        print ips
    return ips


def Entropy(labels, base=2):
    probs = pd.Series(labels).value_counts() / len(labels)
    en = stats.entropy(probs, base=base)
    return en

def Entropy2(labels, base=2):
    data = labels.value_counts()
    en = stats.entropy(data, base = base)



if __name__ == "__main__":
 #   ips = Get_IP("result/skew-1.0.pcap")
    ips = Get_IP("../data/s3.2.pcap")
    real_entropy = []

    ips_count = np.size(ips)
    # 2^13 is the observation windows value,
    # you can change it as you wish,
    # note keeping the same with "sw_rules/s11-cli.input register R_log2_m"
    windows_size = int(math.pow(2,13))
    windows_count = ips_count / windows_size
    for i in range(int(windows_count)):
        temp_e = Entropy(ips[i*windows_size:(i+1)*windows_size])
        print temp_e
        real_entropy.append(temp_e)
    print real_entropy
    data = pd.DataFrame({'entropy':real_entropy},index=None)
 #   data.to_csv('result/ddostrace.csv',index=False)
