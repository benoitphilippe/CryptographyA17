#!bin/python3
#encoding=utf-8

""" Classe pour le triple chiffrement """

from abc import abstractmethod
from encrypter import Encrypter
from des import DES

class EDE(Encrypter):
    """ Encrypt-Decrypt-Encrypt class
    
   Permet d'effectuer un triple chiffrement avec la fonction implémentée """

    def __init__(self, encrypter=None, keys=None):
        """ Initialise la classe
       
        :param encrypter: un objet qui implémente la classe abstraite encrypter
        :type encrypter: Encrypter
        :param keys: les clées pour le triple chiffrement sous la forme [key, key, key]
        :type keys: list(bytes)"""
        if encrypter is not None:
            self.set_encrypter(encrypter)
        if keys is not None:
            self.set_keys(keys)
    
    def set_encrypter(self, encrypter):
        """ Permet d'affecter un objet Encrypter à l'attribut concerné,
        l'encrypter peut ne pas avoir de clés initilisés

        :param encrypter: un objet qui implémente la classe abstraite encrypter
        :type encrypter: Encrypter """

        if isinstance(encrypter, Encrypter):
            self.__encrypter = encrypter
        else:
            raise "must be an instance of Encrypter"
    
    def get_encrypter(self):
        """ Retourne l'attribut encrypter
        :return: encrypter
        :rtype: Encrypter """
        return self.__encrypter
    
    def set_keys(self, keys):
        """ Initialise les clées qui seront utilisé pour le chiffrement,
        Dans le cas d'un triple chiffrement, soir on donne un tableau de trois
        bytes, soit un seule bytes mais qui représente les trois clées
        
        :param keys: un tableau de 3 clées [key, key, key]
                    ou un bytes totale
        :type keys: list(bytes) ou bytes"""

        if isinstance(keys, bytes):
            # on doit séparer ça en trois parties
            if len(keys) % 3 == 0:
                size = len(keys)//3
                tab_keys = [keys[0:size], keys[size:2*size], keys[2*size:3*size]]
                self.__keys = tab_keys
            else:
                raise "wrong size for keys"
        elif isinstance(keys, list) and len(keys) == 3:
            self.__keys = keys
        else:
            raise TypeError("keys doit un être un tableau de 3 bytes")
    
    def get_keys(self):
        """ Accesseur pour la clé totale
        
        :return: la clé totale
        :rtype: bytes"""
        return self.__keys[0] + self.__keys[1] + self.__keys[2]
        
    
    def get_tab_keys(self):
        """ Accesseur pour l'attribut keys
        
        :return: l'attribut keys sous cette forme [key, key, key]
        :rtype: list(bytes)"""
        return self.__keys

    def crypt(self, block):
        """ On chiffre le block à l'aide de l'encrypter enrigistré
        
        :param block: le block à chiffrer, sa taille dépend de l'encrypter utilisé
        :type: bytes
        :return: le block chiffré
        :rtype: bytes """

        # get encrypter
        encrypter = self.get_encrypter()
        # set encrypter with the first key
        encrypter.set_keys(self.get_tab_keys()[0])
        # crypt
        crypted_block = encrypter.crypt(block)
        # set the second key
        encrypter.set_keys(self.get_tab_keys()[1])
        # uncrypt
        crypted_block = encrypter.uncrypt(crypted_block)
        # set the third key
        encrypter.set_keys(self.get_tab_keys()[2])
        # crypt
        crypted_block = encrypter.crypt(crypted_block)
        # return the result
        return crypted_block

    def uncrypt(self, block):
        """ On déchiffre le block à l'aide de l'encrypter enregistré
        :param block: le block à chiffrer, sa taille dépend de l'encrypter utilisé
        :type block: bytes
        :return: le block déchiffré
        :rtype: bytes """

        # get encrypter
        encrypter = self.get_encrypter()
        # set encrypter with the first key
        encrypter.set_keys(self.get_tab_keys()[2])
        # crypt
        uncrypted_block = encrypter.uncrypt(block)
        # set the second key
        encrypter.set_keys(self.get_tab_keys()[1])
        # uncrypt
        uncrypted_block = encrypter.crypt(uncrypted_block)
        # set the third key
        encrypter.set_keys(self.get_tab_keys()[0])
        # crypt
        uncrypted_block = encrypter.uncrypt(uncrypted_block)
        # return the result
        return uncrypted_block

def main():
    """ montre comment effectuer le triple DES """
    des = DES()
    keys = [b'12345678', b'abcdefgp', b'87654321']
    tripleDES = EDE(des, keys)
    block = b'12345678'
    crypted_block = tripleDES.crypt(block)
    print(crypted_block)
    uncrypted_block = tripleDES.uncrypt(crypted_block)
    print(uncrypted_block)

if __name__ == '__main__':
    main()
