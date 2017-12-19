#!/usr/bin/env python3.6
#encoding=utf-8

""" Définits toutes les classes qui effectues un schéma de chiffrement particulier """

import sys
from encrypter import Encrypter
from random import seed, getrandbits
from Cryptodome.Util.strxor import strxor
from abc import abstractmethod


class ECB(Encrypter):
    """ Simple chiffrement block à block """
    def __init__(self, encrypter=None, keys=None):
        """ Initialise la classe
        
        :param encrypter: la classe qui va chiffrer notre block, 
        celui-ci peut être initialisé avec une clé valide et prêt à l'emploi
        :type encrypter: Encrypter
        :param keys: la clé pour le chiffrement
        :param keys: bytes"""
        if encrypter is not None:
            self.set_encrypter(encrypter)
        if keys is not None:
            self.set_keys(keys)
    
    def set_encrypter(self, encrypter):
        """ Setter for encrypter """
        if isinstance(encrypter, Encrypter):
            self.__encrypter = encrypter
        else:
            raise "encrypter is not an instance of Encrypter class"

    def get_encrypter(self):
        """ accesseur de encrypter"""
        return self.__encrypter

    def set_keys(self, keys):
        """ Setter de keys, la clé est directement sauvegardé dans l'encrypter """
        if self.__encrypter is not None:
            self.get_encrypter().set_keys(keys)
        else:
            raise "Init encrypter before keys"
    
    def get_keys(self):
        """ accesseur de keys """
        return self.get_encrypter().get_keys()

    def crypt(self, block):
        """ Crypt le block"""
        return self.get_encrypter().crypt(block)
    
    def uncrypt(self, block):
        """ Uncrypt le block """
        return self.get_encrypter().uncrypt(block)

class ModeEncrypter(Encrypter):
    """ La classe abstraite des modes de chiffrement"""
    def __init__(self, encrypter=None, keys=None):
        """ Initialise la classe
        
        :param encrypter: la classe qui va chiffrer notre block,
        celle-ci peut être initilisé directement avec une clé
        :type encrypter: Encrypter
        :param keys: la clé pour le chiffrement
        :param keys: bytes"""
        if encrypter is not None:
            self.set_encrypter(encrypter)
        if keys is not None:
            self.set_keys(keys)
        self.set_vector(None)
    
    def set_encrypter(self, encrypter):
        """ Setter for encrypter """
        if isinstance(encrypter, Encrypter):
            self.__encrypter = encrypter
        else:
            raise "encrypter is not an instance of Encrypter class"

    def get_encrypter(self):
        """ accesseur de encrypter"""
        return self.__encrypter

    def set_keys(self, keys):
        """ Setter de keys, elle sera sauvegarder directement dans l'objet encrypter """
        if self.__encrypter is not None:
            self.get_encrypter().set_keys(keys)
        else:
            raise "Init encrypter before keys"
    
    def get_keys(self):
        """ accesseur de keys """
        return self.get_encrypter().get_keys()

    def set_vector(self, vector):
        self.__vector = vector
    
    def get_vector(self):
        return self.__vector
    
    def reset(self):
        """ Permet la réinitialisation de vector"""
        self.set_vector(None)

    def init_vector(self, block_len, keys=None):
        """ Permet l'initialisation de la première valeur du vecteur en fonction
        du block et de la clé insérée
        
        :param block_len: la taile du block à chiffrer
        :type block_len: int
        :param keys: la clé à utilisé pour l'initilisation,
        si cette dernière est None, on se servira de celle de encrypter
        :type keys: bytes """

        if keys is None:
            # On va utiliser pseudorandom initilisé avec la clé pour créer notre vecteur initiale
            seed(self.get_keys())
        else:
            seed(keys)

        # Le vecteur doit être de la même taille que le block
        vector = (getrandbits(8*block_len)).to_bytes(block_len, byteorder=sys.byteorder)
        # on a notre vecteur initiale, on le sauvegarde en attribut
        self.set_vector(vector)
    
    @abstractmethod
    def crypt(self, block):
        """ methode abstraite pour le chiffrement """
        raise NotImplementedError
    
    @abstractmethod
    def uncrypt(self, block):
        """ méthode abstraite pour le déchiffrement """
        raise NotImplementedError

class CBC(ModeEncrypter):
    """ chiffrement block à block en chaîne"""
    def crypt(self, block):
        """ Crypt le block"""
        # le vecteur doit être initilisé si on ne s'en ai jamais servi
        if self.get_vector() is None:
            self.init_vector(len(block))
        # premièrement on xor avec le vecteur
        crypted_block = strxor(self.get_vector(), block)
        # Puis on chiffre le tout
        crypted_block = self.get_encrypter().crypt(crypted_block)
        # enfin on sauvegarde le résultat dans le vecteur
        self.set_vector(crypted_block)
        # on retourne le résulat
        return crypted_block
    
    def uncrypt(self, block):
        """ Uncrypt le block"""
         # le vecteur doit être initilisé si on ne s'en ai jamais servi
        if self.get_vector() is None:
            self.init_vector(len(block))
        # Premièrement on déchiffre le block
        uncrypted_block = self.get_encrypter().uncrypt(block)
        # on xor le résultat avec notre vecteur
        uncrypted_block = strxor(self.get_vector(), uncrypted_block)
        # notre vecteur prend la valeur du block
        self.set_vector(block)
        # On retourne le texte claire
        return uncrypted_block

class PCBC(ModeEncrypter):
    """ chiffrement block à block en chaîne avec propagation"""
    def crypt(self, block):
        """ Crypt le block"""
        # le vecteur doit être initilisé si on ne s'en ai jamais servi
        if self.get_vector() is None:
            self.init_vector(len(block))
        # premièrement on xor avec le vecteur
        crypted_block = strxor(self.get_vector(), block)
        # Puis on chiffre le tout
        crypted_block = self.get_encrypter().crypt(crypted_block)
        # enfin on sauvegarde le résultat dans le vecteur
        self.set_vector(strxor(crypted_block, block))
        # on retourne le résulat
        return crypted_block
    
    def uncrypt(self, block):
        """ Uncrypt le block"""
         # le vecteur doit être initilisé si on ne s'en ai jamais servi
        if self.get_vector() is None:
            self.init_vector(len(block))
        # Premièrement on déchiffre le block
        uncrypted_block = self.get_encrypter().uncrypt(block)
        # on xor le résultat avec notre vecteur
        uncrypted_block = strxor(self.get_vector(), uncrypted_block)
        # notre vecteur prend la valeur du block
        self.set_vector(strxor(block, uncrypted_block))
        # On retourne le texte claire
        return uncrypted_block

class CFB(ModeEncrypter):
    """ chiffrement à rétroaction """
    def crypt(self, block):
        """ Crypt le block"""
        # le vecteur doit être initilisé si on ne s'en ai jamais servi
        if self.get_vector() is None:
            self.init_vector(len(block))
        # on chiffre le vecteur
        crypted_block = self.get_encrypter().crypt(self.get_vector())
        # on le xor avec le block
        crypted_block = strxor(block, crypted_block)
        # le prochain vecteur est le chiffré
        self.set_vector(crypted_block)
        # on retourne le chifré
        return crypted_block
    
    def uncrypt(self, block):
        """ Uncrypt le block"""
         # le vecteur doit être initilisé si on ne s'en ai jamais servi
        if self.get_vector() is None:
            self.init_vector(len(block))
        # on chiffre le vecteur    
        uncrypted_block = self.get_encrypter().crypt(self.get_vector())
        # on xor avec le block
        uncrypted_block = strxor(uncrypted_block, block)
        # le prochain vecteur est ce block
        self.set_vector(block)
        # On retourne le texte claire
        return uncrypted_block

class OFB(ModeEncrypter):
    """ Sortie à rétroaction """
    def crypt(self, block):
        """ Crypt le block"""
        # le vecteur doit être initilisé si on ne s'en ai jamais servi
        if self.get_vector() is None:
            self.init_vector(len(block))
        # on chiffre le vecteur
        crypted_block = self.get_encrypter().crypt(self.get_vector())
        # le prochain vecteur est l'étape intermédiaire
        self.set_vector(crypted_block)
        # on le xor avec le block
        crypted_block = strxor(block, crypted_block)
        # on retourne le chifré
        return crypted_block
    
    def uncrypt(self, block):
        """ Uncrypt le block"""
         # le vecteur doit être initilisé si on ne s'en ai jamais servi
        if self.get_vector() is None:
            self.init_vector(len(block))
        # on chiffre le vecteur    
        uncrypted_block = self.get_encrypter().crypt(self.get_vector())
        # le prochain vecteur est l'étape intermédiaire
        self.set_vector(uncrypted_block)
        # on xor avec le block
        uncrypted_block = strxor(uncrypted_block, block)
        # On retourne le texte claire
        return uncrypted_block

class CTR(ModeEncrypter):
    """ Mode compteur"""
    def incremente_vector(self):
        """ Incrémente le vecteur de 1 """
        length = len(self.get_vector())
        int_vector = int.from_bytes(self.get_vector(), sys.byteorder)
        int_vector = (int_vector + 1) % (2**(length*8))
        vector = int_vector.to_bytes(length, sys.byteorder)
        self.set_vector(vector)

    def crypt(self, block):
        """ chiffrement du block """
        # le vecteur doit être initilisé si on ne s'en ai jamais servi
        if self.get_vector() is None:
            self.init_vector(len(block))
        # on chiffre le vecteur
        crypted_block = self.get_encrypter().crypt(self.get_vector())
        # on xor le tout pour obtenir le chiffré
        crypted_block = strxor(crypted_block, block)
        # on incrémente le vecteur
        self.incremente_vector()
        # on retourne le résultat
        return crypted_block

    def uncrypt(self, block):
        """ Déchiffrement du block """
        # same as encryption
        return self.crypt(block)
        
