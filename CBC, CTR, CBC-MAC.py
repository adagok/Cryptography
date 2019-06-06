#!/usr/bin/env python3
# -*- coding: utf-8 -*-


####################################################################################################################################

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
from string import printable
from itertools import product
from Cryptodome.Util.strxor import strxor
from sample_cipher import Sample_Cipher
from Crypto.Cipher import AES

def slice_into_block(message, block_size):
        len_message = len(message)
        assert(len_message >= block_size)
        return [message[i: i + block_size] for i in range(0, len_message, block_size)]

def q1_enc_cbc_mode(key, message, iv, cipher=Sample_Cipher):
    """Implement CBC Mode encryption"""
    
    pad = lambda s: s + (cipher.BLOCK_SIZE - len(s) % cipher.BLOCK_SIZE) * chr(cipher.BLOCK_SIZE - len(s) % cipher.BLOCK_SIZE)
    unpad = lambda s : s[0:-ord(s[-1])]
    msgs =slice_into_block(pad(message), cipher.BLOCK_SIZE)
    ciphers=""

    first=binascii.hexlify(strxor(binascii.unhexlify(iv),msgs[0].encode())).decode()
    for i in range(1,len(msgs)+1):
        
        c=cipher.encipher(key,first)
        ciphers+=c
        if i==len(msgs):
            break
        else:
            first=binascii.hexlify(strxor(binascii.unhexlify(c),msgs[i].encode())).decode()
        
    return ciphers
def q1_dec_cbc_mode(key, ciphertext, iv, cipher=Sample_Cipher):
    """Implement CBC Mode **decryption**"""
    
    pad = lambda s: s + (cipher.BLOCK_SIZE - len(s) % cipher.BLOCK_SIZE) * chr(cipher.BLOCK_SIZE - len(s) % cipher.BLOCK_SIZE)
    unpad = lambda s : s[0:-ord(s[-1])]
    cipher1=slice_into_block(ciphertext, cipher.BLOCK_SIZE*2)
    msg=cipher.decipher(key,cipher1[0])
    msgs=""
    first=binascii.hexlify(strxor(binascii.unhexlify(iv),binascii.unhexlify(msg))).decode()
    msgs+=first
    for i in range(1, len(cipher1)):
        msg=cipher.decipher(key,cipher1[i])
        last=binascii.hexlify(strxor(binascii.unhexlify(cipher1[i-1]),binascii.unhexlify(msg))).decode()
        msgs+=last
   
    return unpad(binascii.unhexlify(msgs).decode()) 


def q2_enc_ctr_mode(key, message, nonce, cipher=Sample_Cipher):
        """Implement Counter (CTR) Mode encryption"""
    
    pad = lambda s: s + (cipher.BLOCK_SIZE - len(s) % cipher.BLOCK_SIZE) * chr(cipher.BLOCK_SIZE - len(s) % cipher.BLOCK_SIZE)
    unpad = lambda s : s[0:-ord(s[-1])]
    msgs =slice_into_block(pad(message), cipher.BLOCK_SIZE)
    cipher2=""
    for i in range(len(msgs)):
        counter = '%08x' % i 
        block=cipher.encipher(key,nonce+counter)
        first=''.join([chr(int(x)) for x in list(binascii.hexlify(strxor(binascii.unhexlify(block),msgs[i].encode())))])
        cipher2+=first
    return cipher2[:(len(message)*2)] 

def q2_dec_ctr_mode(key, ciphertext, nonce, cipher=Sample_Cipher):
        """Implement Counter (CTR) Mode **decryption**"""
    
    def pad(msg,block_size):
        length=block_size-(len(msg)%block_size)
        if (length//2)<=15:
            hex1=('0'+hex(length//2)[2:])*(length//2)
        else:
            hex1=hex(length//2)[2:]*(length//2)
                
        msg=msg+hex1
        return msg
    unpad = lambda s : s[0:-ord(s[-1])]
    cphs =slice_into_block(pad(ciphertext,cipher.BLOCK_SIZE*2), cipher.BLOCK_SIZE*2)
    
    msgs=""
    for i in range(len(cphs)):
        counter = '%08x' % i 
        block=cipher.encipher(key,nonce+counter)
        first=''.join([chr(int(x)) for x in list(binascii.hexlify(strxor(binascii.unhexlify(block),binascii.unhexlify(cphs[i]))))])
        msgs+=first
    
    return ''.join([chr(int(x)) for x in list((binascii.unhexlify(msgs))[:len(ciphertext)//2])]) 
def bytes_to_string(the_input):
    """ Take in a list of bytes, and return the string they correspond to. Unlike the prior question, here you should return a raw bitstring and not the hex values of the bytes! As a result, the output need not always be printable. (This should effectively "undo" the question 1.)

    Example test case:
 
        [116, 101, 115, 116] -> "test"

    """

    return ''.join([chr(int(x)) for x in the_input])

def q3_break_cbc_mac():
    """Break CBC-MAC if used as a hash function"""

    def aes_encipher(key, plaintext):
        enciphering_suite_1 = Cipher(algorithm=algorithms.AES(bytes.fromhex(key)), mode=modes.ECB(), backend=default_backend()).encryptor()
        cipherText1 = enciphering_suite_1.update(bytes.fromhex(plaintext)).hex()
        
        return cipherText1 
    def cbcmac(key, message, iv):
        BLOCK_SIZE = 16

        def Encipher(key, X):
            assert(len(key) == BLOCK_SIZE*2)
            assert(len(X)   == BLOCK_SIZE*2)        
            return bytes.fromhex(aes_encipher(key,X)) 

        def slice_into_blocks(message, block_size):
            len_message = len(message)
            assert(len_message >= block_size)
            return [message[i: i + block_size] for i in range(0 , len_message, block_size)]

        len_message = len(message)
        num_rounds = len_message//BLOCK_SIZE
        msg_blocks = slice_into_blocks(message, BLOCK_SIZE)

        assert(len(msg_blocks) == num_rounds)
        if not iv:
            iv = bytes([0 for _ in range(BLOCK_SIZE)]) # All zeros IV to start with

        for msg_block in msg_blocks:
            block_input = strxor(msg_block.encode('ascii'), iv)
            block_output = Encipher(key.encode('ascii').hex(), block_input.hex())
            iv = block_output
        return block_output.hex()

    M = 'print("CBC-MAC is a very strong hash function!")'
    def hash_from_cbcmac(M, iv=None):
        K = 'very secret key!' 
        return cbcmac(K, M, iv)

    message_needed='print("CBC-MAC not a hash")#'
    trialm21=message_needed[:16]
    hash_m1=hash_from_cbcmac(trialm21)
    trialm2=message_needed[16:]

    print_m3=""
    poss_m2=""
    last=b'U\x1e\x15\xf4\xb2D\xe9=\x83\xdd\xac\xf1\xa0\xc3\xc1\xcd'
    
    poss=product(printable,repeat=4)
    
    for pos in poss:

        pos="".join([e for e in pos])
        trialm2Imp= trialm2+ pos
        hash_m2=hash_from_cbcmac(trialm2Imp, binascii.unhexlify(hash_m1))
        trialm3=strxor(binascii.unhexlify(hash_m2),last)
        
        #HERE I go through every possibility to see if I can find printable m3 and of length 16
        try:
                
                if(str.isprintable(trialm3.decode()) and len(trialm3.decode())==16):
                    
                    poss_m2=trialm2Imp
                    print_m3=trialm3.decode()
                    break
        except:
                pass
    final=trialm21+poss_m2 +print_m3
    return final











        
