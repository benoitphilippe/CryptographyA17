#!/usr/bin/env python3.6
#encoding=utf-8

""" Définit la fonction de hashage du projet"""
from hashlib import sha256

class Hasher():
    def __init__(self, block=None):
        """ Construteur de la classe"""
        # initialisation de la classe
        if block is not None:
            self.block = block

    def digest(self, block=None):
        """ Hash le block"""
        if block is not None:
            self.block = block
        # fonction de hashage à appliquer sur block
        # pour 
        return sha256(block).digest()