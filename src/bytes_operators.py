#!/usr/bin/env python3.6
#encoding=utf-8

import sys

def rol(val, r_bits, max_bits):
    """ Fonction de rotation à gauche
    
    :param val: nombre qui subit la rotation
    :type val: int
    :param r_bits: nombre de rotation à effectué
    :type r_bits: int
    :param max_bits: le nombre maximal de bits sur lequel on tourne
    :type max_bits: int
    :return: le nobmre après rotation à gauche
    :rtype: int"""
    return (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def ror(val, r_bits, max_bits):
    """ Fonction de rotation à droie
    
    :param val: nombre qui subit la rotation
    :type val: int
    :param r_bits: nombre de rotation à effectué
    :type r_bits: int
    :param max_bits: le nombre maximal de bits sur lequel on tourne
    :type max_bits: int
    :return: le nobmre après rotation à droite
    :rtype: int"""
    return ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def add_bytes(bytes1, bytes2, max_bytes):
    int1 = int.from_bytes(bytes1, sys.byteorder)
    int2 = int.from_bytes(bytes2, sys.byteorder)
    result = (int1 + int2) % pow(2, max_bytes*8)
    return result.to_bytes(max_bytes, sys.byteorder)

def sub_bytes(bytes1, bytes2, max_bytes):
    int1 = int.from_bytes(bytes1, sys.byteorder)
    int2 = int.from_bytes(bytes2, sys.byteorder)
    result = (int1 - int2) % pow(2, max_bytes*8)
    return result.to_bytes(max_bytes, sys.byteorder)

def concat_bytes(tab_bytes):
    result = b''
    for word in tab_bytes:
        result = result + word
    return result

def split_to_word(big_block, bytes_by_word):
    # calcul du nombre de mots à fournir N
    N = len(big_block) // bytes_by_word
    W = []
    for i in range(N):
        W.append(big_block[(i*(bytes_by_word)):((i+1)*(bytes_by_word))])
    return W