#!/usr/bin/env python3
# -*- coding: utf-8 -*-

####################################################################################################################################


import binascii
import lab5_helper
from Cryptodome.Util.strxor import strxor
from string import printable
from random import choices

def q1_forge_mac(message, leaky_hmac_verify=lab5_helper.leaky_hmac_verify_example):
    """Timing attack on HMAC's equality test """
    binTag='0'*160 

    i=0
    hold=0
    while(i<160):
        newTag=(hex(int(binTag, 2))[2:]).zfill(40)
        output=leaky_hmac_verify(message, newTag)
        if(output[0]==True):
            return newTag
        hold=int(binTag[output[1]])
        
        i=output[1]
        binTag=(binTag[0:i]+str((hold+1)%2)+ binTag[i+1:]).zfill(160)
    return newTag
                
    

def q2_simple_aes_cache_attack(leaky_encipher=lab5_helper.leaky_encipher_example):
    """Simple cache timing attack on AES"""

    def get_rand_string(perm_size):
        return ''.join(choices(printable, k=perm_size))
    index=0
    
    matrixP=[]
    last_round_key=""
    check=[0,0]
    intersection=[0,0,0]

    for i in range(0,31,2):
        matrixK=[]
        for s in range(10):
            index+=1
            plaintext=get_rand_string(16)
            cipher,cache=leaky_encipher(plaintext.encode())
            lists=[]
            hexC=binascii.hexlify(cipher)
            firstByte=hexC[i:i+2]
            poss=[]
            for j in range(256):
                key="{:02x}".format(j)
                xor=int(strxor(binascii.unhexlify(firstByte),binascii.unhexlify(key)).hex(),16)
                b=lab5_helper.Sinv(xor)
                poss.append(b)
            key_poss=[]
            for k,p in enumerate(poss):
                if p in cache:
                    key_poss.append(k)

            matrixK.append(key_poss)
            matrixP.append(poss)

        temp=set(matrixK[0])
        for m in range(len(matrixK)):
            temp=temp&set(matrixK[m])
        ans=list(temp)

        if len(ans)!=1:
            print("not done")
            break
        else:
            res=hex(ans[0])[2:]
            if len(res) ==1:
                res='0'+res
            last_round_key+=res
    return last_round_key

   


def q3_realistic_aes_cache_attack(less_leaky_encipher=lab5_helper.less_leaky_encipher_example):
    """Realistic cache timing attack on AES"""

    def get_rand_string(perm_size):
        return ''.join(choices(printable, k=perm_size))
    index=0
    
    matrixP=[]
    last_round_key=""

    check=[0,0]
    intersection=[0,0,0]

        
    
    for i in range(0,31,2):
        matrixK=[]
        for s in range(40):
            index+=1
            plaintext=get_rand_string(16)
            cipher,cache=less_leaky_encipher(plaintext.encode())
            lists=[]
            hexC=binascii.hexlify(cipher)
            firstByte=hexC[i:i+2]
            poss=[]
            for j in range(256):
                key="{:02x}".format(j)
                xor=int(strxor(binascii.unhexlify(firstByte),binascii.unhexlify(key)).hex(),16)
                b=lab5_helper.Sinv(xor)
                poss.append(b)
            key_poss=[]
            for k,p in enumerate(poss):
                if p>>4 in cache:
                    key_poss.append(k)

            matrixK.append(key_poss)
            matrixP.append(poss)

        temp=set(matrixK[0])
        for m in range(len(matrixK)):
            temp=temp&set(matrixK[m])
        ans=list(temp)

        if len(ans)!=1:
            print("not done")
            break
        else:
            res=hex(ans[0])[2:]
            if len(res) ==1:
                res='0'+res
            last_round_key+=res
    return last_round_key
