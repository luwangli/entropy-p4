import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

df = pd.read_csv('../result_0.05.csv')
print df

df1 = df[0:27]

#AL = ['euclid','sample0.1','sample0.01','fs','real']
AL = ['sample0.1','sample0.01','fs','real']
COLOR = ['#1b9e77','#d95f02','#7570b3','#e6ab02','#66a61e']
MARKER = ['o','s','p','d','<']

x = [ j for j in range(1,28,1)]

i = 0;
for al in AL:
    y = df1[al]
    plt.plot(x,y,color=COLOR[i],marker=MARKER[i],markersize=4,linestyle='-.')
    i = i+1

#y = df1['real']
#print y
#plt.plot(x,y)
plt.legend(['sample0.1','sample0.01','FS','real'])
plt.show()
