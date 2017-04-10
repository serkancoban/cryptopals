import base64
import codecs
from operator import itemgetter
from collections import OrderedDict

english_freq=[
0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
0.00978, 0.02360, 0.00150, 0.01974, 0.00074                   
]
english_freq_inc_space=[
0.0651738, 0.0124248, 0.0217339, 0.0349835, 0.1041442, 0.0197881,
0.0158610, 0.0492888, 0.0558094, 0.0009033, 0.0050529, 0.0331490,
0.0202124, 0.0564513, 0.0596302, 0.0137645, 0.0008606, 0.0497563,
0.0515760, 0.0729357, 0.0225134, 0.0082903, 0.0171272, 0.0013692, 
0.0145984, 0.0007836, 0.1918182
]
#english_letters=b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
english_letters=b'abcdefghijklmnopqrstuvwxyz'

def bytes_xor(a, b) :
    return bytes(x ^ y for x, y in zip(a, b))
def string_xor(a, b):
    output=b''
    for i in range(0,len(a)):
        output+=bytes_xor(a[i:i+1],b)
    return output

def hexToBytes(input):
    output=bytes.fromhex(input)
    return output
def bytesToBase64(input):
    output=base64.b64encode(input)
    return output
def fixedHexXor(h1,h2):
    output=hex(h1 ^ h2)
    return output
def getChi2(input):
    count=[]
    ignored=0
    total=0
    lower=0
    for i in range(0,27): count.append(0)
    for i in range(0,len(input)):
        c=ord(input[i])
        if(c >= 65 and c <= 90):
            count[c-65]+=1
        elif(c >= 97 and c <= 122):
            count[c-97]+=1
            lower+=1
        elif(c > 32 and c <= 126):
            ignored+=1
        elif(c==32):
            count[26]+=1
            lower+=1


    chi2=0
    for i in range(0,27):
        observed=count[i]
        expected=(len(input)-ignored) * english_freq_inc_space[i]
        diff=observed-expected
        chi2+=diff*diff/expected
    return chi2

def getLowerCaseCount(input):
    lower=0
    for i in range(0,len(input)):
        c=ord(input[i])
        if((c >= 97 and c <= 122) or c==32):
            lower+=1
    return lower

def hamming2(s1, s2):
    """Calculate the Hamming distance between two strings"""
    #s1_bytes=bytes(s1,'ascii')
    #s2_bytes=bytes(s2,'ascii')
    s1_bits=''.join(["{0:08b}".format(x) for x in s1])
    s2_bits=''.join(["{0:08b}".format(x) for x in s2])
    assert len(s1_bits) == len(s2_bits)
    return sum(c1 != c2 for c1, c2 in zip(s1_bits, s2_bits))

def cryptos1c1():
    str='49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    print (bytesToBase64(hexToBytes(str)))

def cryptos1c2():
    h1=0x1c0111001f010100061a024b53535009181c
    h2=0x686974207468652062756c6c277320657965
    print (fixedHexXor(h1,h2))

def cryptos1c3():
    l=[]
    xorcount=0
    xorstr=b''
    maxcount=0
    b='1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    for i in range(0,95):
        xorstr=string_xor(hexToBytes(b),bytes(chr(i+32).encode()))
        l.append(xorstr)
        xorcount=getLowerCaseCount(l[i].decode())
        if(xorcount > maxcount):
            maxcount=xorcount
            index=i
    print(l[index])


def cryptos1c4():
    l=[]
    d={}
    count=0
    xorcount=0
    maxcount=0
    with open(r'cryptopals_files\4.txt') as f:
        for line in f:
            b=hexToBytes(line.strip())
            for i in range(0,95):
                xored=string_xor(b,bytes(chr(i+32).encode()))
                l.append(xored)
                xorcount=getLowerCaseCount(l[count].decode(errors='ignore'))
                if(xorcount > maxcount):
                    maxcount=xorcount
                    index=count
                count+=1
        print(l[index])


def cryptos1c5():
    s="Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    count=0
    l=b''
    for f in s:
        if(count%3==0):
            l+=bytes_xor(f.encode(),'I'.encode())
            count+=1
        elif(count%3==1):
            l+=bytes_xor(f.encode(),'C'.encode())
            count+=1
        elif(count%3==2):
            l+=bytes_xor(f.encode(),'E'.encode())
            count+=1
    print(s)
    print(l.hex())

def cryptos1c6():
    with open(r'cryptopals_files\\6.txt') as f:
        data=f.read().replace('\n', '')
        data_decoded=base64.b64decode(data)
        #print(data_decoded)
        for key in range(2,40):
            edit_distance=0
            edit_distance+=hamming2(data_decoded[0:key], data_decoded[key:2*key])
            edit_distance/=key
            print (edit_distance)

        

        #print(l[index])
        #print(chr(index+32))


def main():
    #cryptos1c1()
    #cryptos1c2()
    #cryptos1c3()
    #cryptos1c4()
    #cryptos1c5()
    cryptos1c6()
if __name__ == "__main__":
    main()




