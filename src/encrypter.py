#!/usr/bin/env python3.6
#encoding=utf-8

""" Une classe abtraite qui définit les méthodes que 
doit posséder une classe valide d'encryption """

from abc import ABC, abstractmethod

class Encrypter(ABC):
    """ La classe abstraite encrytpter """

    @abstractmethod
    def crypt(self, block):
        """ La fonction de chiffrement, à implémenter"""
        raise NotImplementedError
    
    @abstractmethod
    def uncrypt(self, block):
        """ La fonction de déchiffrement, à implémenter"""
        raise NotImplementedError
    
    @abstractmethod
    def set_keys(self, keys):
        """ Initialise les clés pour le chiffrement/déchiffrement """
        raise NotImplementedError
    
    @abstractmethod
    def get_keys(self):
        """ Accesseur pour l'attribut keys """
        raise NotImplementedError