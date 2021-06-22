def data_convert(data):
    int_part = data >> 4
    dec_part = data & 0xf
    t1 = dec2bin2(dec_part)
    while len(t1) < 4:
        t1.insert(0, 0)
    dec_result = bin2dec(t1)


    result = int_part + dec_result
    return result

def dec2bin2(x):
    base = [0, 1]
    mid = []
    while True:
        if x == 0: break
        x, rem = divmod(x, 2)
        mid.append(base[rem])
    mid.reverse()
    return mid


def bin2dec(b):
    d = 0
    for i, x in enumerate(b):
        d += 2 ** (-i - 1) * x
    return d



#Data = ['6d','6f','6c','6a','68','6d','6d','6c','69','68','6a','6d','6c','6a','6b','69',
#'67','6a','6c','6a','6c','6d','68','68','70','6e','6f','6e','6f']

Data = ['99','99','94','92','8c','98','9e','a3','a1','a2','9b','9c','97',
'9b','93','8f','8f','90','8f','90','8c','88','89','88','91','96','91','90','8d']
for data in Data:
    data1=int(data,16)
   # print data1
    result = data_convert(data1)
    print result
#result = data_convert(data)
#print result
