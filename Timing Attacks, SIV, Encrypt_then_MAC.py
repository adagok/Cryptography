#!/usr/bin/env python3
# -*- coding: utf-8 -*-

####################################################################################################################################

import base64
import operator
from Cryptodome.Util.Padding import unpad
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from Cryptodome.Hash import CMAC
from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor
from Cryptodome.Hash import HMAC
from Cryptodome.Hash import SHA as SHA1
import lab6_helper
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher

def slice_into_block(message, block_size):
    len_message = len(message)
    assert(len_message >= block_size)
    return [message[i: i + block_size] for i in range(0, len_message, block_size)]
class Sample_Cipher(object):
    def __init__(self):
        """
            Sample Cipher class that will be passed to some of the methods in the lab
        """
        self.BLOCK_SIZE = 16  # bytes
        return

    def sub_word(self, word):
        """performs an s-box substitution on the 8-bit input "word"

        NOTE: Using this function directly will NOT give you full-credit for question 1

        Args:
            word    (bytes/bytearray): bytes/bytearray object of length 8 bits (1 byte).

        Return:
            bytes : bytes object of length 8 bits (1 byte)
        """
        sbox = (  # Sample S-Box
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        )
        return bytes([sbox[b] for b in word])

    def inv_sub_word(self, word):
        """ performs an inverse s-box substitution on the 8-bit input "word"

        NOTE: Using this function directly will NOT give you full-credit for question 1

        Args:
            word    (bytes/bytearray): bytes/bytearray object of length 8 bits (1 byte).

        Return:
            bytes : bytes object of length 8 bits (1 byte)
        """
        sbox_inv = (  # Sample S-Box-Inverse
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        )
        return bytes([sbox_inv[b] for b in word])

    def encipher(self, key, message):
        """preforms an encipher on the input "message" given the key "key"

        Args:
            key       (str):   hex-encoded string of length self.BLOCK_SIZE bytes.
            message   (str):   hex-encoded string of length self.BLOCK_SIZE bytes.

        Return:
            str : hex-encoded string of length self.BLOCK_SIZE bytes.
        """
        return self.__TOY(bytes.fromhex(message), bytes.fromhex(key)).hex()

    def __TOY(self, message, key):
        assert(len(key) == self.BLOCK_SIZE)
        assert(len(message) % self.BLOCK_SIZE == 0)

        pre_xor = strxor(message, key)
        sub_word = b''.join(self.sub_word(word)
                            for word in slice_into_block(pre_xor, self.BLOCK_SIZE))
        post_xor = strxor(sub_word, key)

        return post_xor

    def decipher(self, key, ciphertext):
        """preforms a TOY decipher on the self.BlOCK_SIZE length input "ciphertext" given the key "key"

        Args:
            key         (str):   hex-encoded string of self.BlOCK_SIZE length
            ciphertext  (str):   hex-encoded string of self.BlOCK_SIZE length

        Return:
            str : hex-encoded string of self.BlOCK_SIZE length
        """
        return self.__TOY_inv(bytes.fromhex(ciphertext), bytes.fromhex(key)).hex()

    def __TOY_inv(self, ciphertext, key):
        
        assert(len(key) == self.BLOCK_SIZE)
        
        assert(len(ciphertext) % self.BLOCK_SIZE == 0)

        post_xor = strxor(ciphertext, key)
        sub_word = b''.join(self.inv_sub_word(word)
                            for word in slice_into_block(post_xor, self.BLOCK_SIZE))
        pre_xor = strxor(sub_word, key)

        return pre_xor
def q1_encrypt_mac(enc_key, hmac_key, blob):
    """Question 1: Encrypt-then-MAC"""
    
    
    
        
    def remove_pkcs_pad(padded_msg, block_size):
        """Removes PKCS#7 padding if it exists and returns the un-padded message
        Args:
            padded_msg  (bytes/bytearray)  

        ret(bytes/bytearray): un-padded message if the padding is valid, None otherwise 
        """
        padded_msg_len = len(padded_msg)

        # Check the input length
        if padded_msg_len == 0:
            return 'ERROR'.encode()

        # Checks if the input is not a multiple of the block length
        if (padded_msg_len % block_size):
            return 'ERROR'.encode()

        # Last byte has the value
        pad_len = padded_msg[-1]

        # padding value is greater than the total message length
        if pad_len > padded_msg_len:
            return 'ERROR'.encode()

        # Where the padding starts on input message
        pad_start = padded_msg_len-pad_len

        # Check the ending values for the correct pad value
        for char in padded_msg[padded_msg_len:pad_start-1:-1]:
            if char != pad_len:
                return 'ERROR'.encode()

        # remove the padding and return the message
        return padded_msg[:pad_start]
    

    IV=blob[:32]
    length=len(blob)
    tag=blob[(length-40):]
    ciphertext=blob[32:(length-40)]

    if(tag !=lab6_helper.hmacsha1(binascii.unhexlify(hmac_key),binascii.unhexlify(IV+ciphertext))):
        return 'ERROR'
    try:
        ciphert = Cipher(algorithms.AES(binascii.unhexlify(enc_key)), mode=modes.CBC(binascii.unhexlify(IV)), backend=default_backend())
        decryptor = ciphert.decryptor()
        pt=decryptor.update(binascii.unhexlify(ciphertext))
    
        unpt=unpad(pt,16)
        return unpt.decode()

    except:
        return "ERROR"


def q2_siv_mode_enc(enc_key, mac_key, plaintext, associated_data):
    """Question 2 (part 1): Synthetic Initialization Vector (SIV) Authenticated Encryption"""

    tag=CMAC.new(binascii.unhexlify(mac_key), (binascii.unhexlify(associated_data)+plaintext.encode()),ciphermod=AES).digest()

    ciphert = Cipher(algorithms.AES(binascii.unhexlify(enc_key)), mode=modes.CTR(tag), backend=default_backend())
    encryptor = ciphert.encryptor()
    ct=encryptor.update(plaintext.encode())

    return binascii.hexlify(tag).decode()+binascii.hexlify(ct).decode()

def q2_siv_mode_dec(enc_key, mac_key, ciphertext, associated_data):
    """Question 2 (part 2): Synthetic Initialization Vector (SIV) Authenticated Encryption"""

    tag=binascii.unhexlify(ciphertext[:32].encode())
    ct=binascii.unhexlify(ciphertext[32:].encode())
    ciphert = Cipher(algorithms.AES(binascii.unhexlify(enc_key)), mode=modes.CTR(tag), backend=default_backend())
    decryptor = ciphert.decryptor()
    pt=decryptor.update(ct)

    tagPoss=CMAC.new(binascii.unhexlify(mac_key), (binascii.unhexlify(associated_data)+pt),ciphermod=AES).digest()
    if tag != tagPoss:
        return "ERROR"
    else:
        return pt.decode()
    

def q3_block_cipher_timing_attack(leaky_encipher=lab6_helper.leaky_encipher_example):
    """Question 3: Collision timing attack on AES"""

    trials = []
    At=14
    A1t=0
    
    for _ in range(15):
        dic = {}

        for _ in range(200):
            Rand = urandom(At)
            Rand1=urandom(A1t)
            mintrial = 17
            
            byte1 = "01"    
            secondtrial=""
            for i in range(0, 16**2):
                byte2 ="{:02x}".format(i)
                pt = binascii.unhexlify(byte1) + Rand1+binascii.unhexlify(byte2) + Rand
                trial, ct = leaky_encipher(pt)
                if trial <= mintrial:
                    mintrial = trial
                    secondtrial = [byte1, byte2]
                    
                mainTrial = strxor(binascii.unhexlify(secondtrial[0]), binascii.unhexlify(secondtrial[1])).hex()
                    
                if mainTrial not in dic:
                    dic[mainTrial] = 1
                else:
                    dic[mainTrial] += 1
                    
        maxor = max(dic.items(), key=operator.itemgetter(1))[0]
        trials.append(maxor)
        At-=1
        A1t+=1

    plaintext = "this is a adals!"
    tri, leaky = leaky_encipher(plaintext.encode())

    for j in range(0, 16**2):
        key = "{:02x}".format(j)
        poss1rd = key
        for t in trials:
            posskey= strxor(binascii.unhexlify(key), binascii.unhexlify(t)).hex()
            poss1rd = posskey+poss1rd
        possCi = aes_(poss1rd, plaintext.encode())
        if possCi == leaky:
            return poss1rd
    return "NOPE"


def aes_(key, pt):
    permutation = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    ct = permutation.encrypt(pt)
    return ct
