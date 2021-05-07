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


data = 184
result = data_convert(data)
print result
