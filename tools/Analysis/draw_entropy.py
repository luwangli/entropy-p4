import matplotlib.pyplot as plt
import pandas as pd

p4_entropy = pd.read_csv("../result/p4_estimate_entropy.csv",header=None,names=['en_p4'])
real_entropy = pd.read_csv("../result/real_entropy.csv")
print p4_entropy
print real_entropy
#p4_entropy = pd.read_table("../result/p4_estimate_entropy.txt",sep=',')

#print p4_entropy

#print p4_entropy.index_col(0)
#x = [1 ,2 ,3,4,5,]
x= list(range(1,16))
plt.plot(x,p4_entropy.en_p4)
plt.show();



