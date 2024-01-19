def key_scheduling(key):
    sched = [i for i in range(0, 256)]
    
    i = 0
    for j in range(0, 256):
        i = (i + sched[j] + key[j % len(key)]) % 256
        
        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp 
    return sched

def streamXor(data, key, data_len,key_len, shed): 
    counter = 0
    i = 0
    j = i
    while data_len != 0:
      i = i+1
      i = i & 0XFF
      temp = shed[i]
      temp = temp & 0xFF
      j = j + temp
      j = j & 0xFF
      shed[i]  = shed[j]
      shed[j] = temp
      shed_swap = shed[i] + temp
      shed_swap = shed_swap & 0xFF
      data[counter] = data[counter] ^ shed[shed_swap]
      counter = counter +1
      data_len = data_len -1

    return data

def customrc4(data, key, data_len,key_len):
    shed = key_scheduling(key)
    final_result = streamXor(data, key, data_len,key_len, shed)
    print(final_result)


def main():
    data = bytearray(b'\xb2\x16\x17\x9f\x23\x37')
    key =  b'\x29\xc5\xbd\xe6'
    customrc4( data, key, 6, 4)

main()

     
    
