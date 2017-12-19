#!/usr/bin/env python3.6
#encoding=utf-8

""" Contient les classes qui permettent de lire 
et d'écrire dans un fichier en block de bytes"""

from Cryptodome.Util.Padding import pad, unpad
from bytes_operators import concat_bytes

class BlockFileEncrypter():
    """ Class qui permet le chiffrement de l'intégralité d'un fichier
    pour se faire, la classe doit être unitialisé avec un objet qui hérite
    de Encrypter, d'un fichier d'entrée, et du nombre de block qui doit
    être lu.
    
    :param in_file: le nom du fichier d'entrée
    :type in_file: string
    :param encrypter: l'objet encrypter, doit hériter de Encrypter
    :type encrypter: Encrypter
    :param block_size_crypt: le nombre d'octets d'un block à lire pour l'encryption
    :type block_size_crypt: int
    :param out_file: le nom du fichier de sortie, sa valeur par défaut est le fichier d'entrée avec l'extension .crypted
    :type out_file: string
    :param block_size_uncrypt: le nombre d'octets ecrit par un block, si différent block_size_crypt
    :type block_size_uncrypt: int"""

    def __init__(self, in_file, encrypter, block_size_crypt, out_file=None, block_size_uncrypt=None):
        """ Initialisation de l'instance de la classe"""
        self.set_in_file(in_file)
        self.set_encrypter(encrypter)
        self.set_block_size_crypt(block_size_crypt)
        if out_file is not None:
            self.set_out_file(out_file)
        else:
            self.set_out_file(in_file + ".crypted")
        if block_size_uncrypt is not None:
            self.set_block_size_uncrypt(block_size_uncrypt)
        else:
            self.set_block_size_uncrypt(block_size_crypt)
    
    def crypt_to_out(self):
        """ Chiffre le fichier d'entrée dans le fichier de sortie avec encrypter"""
        # ouverture des fichiers concerné
        file_in = open(self.get_in_file(), 'rb')
        file_out = open(self.get_out_file(), 'wb')
        encrypter = self.get_encrypter()
        file = bytes(file_in.read())
        block_size = self.get_block_size_crypt()
        padded_file = pad(file, block_size, style='iso7816')
        blocks = [padded_file[i*block_size:(i+1)*block_size] for i in range(len(padded_file)//block_size)]
        for block in blocks:
            crypted_block = encrypter.crypt(block)
            file_out.write(crypted_block)
        # fermeture des fichiers
        file_in.close()
        file_out.close()

    def uncrypt_to_out(self):
        """ Déchiffre le fichier d'entrée dans le fichier de sortie"""
         # ouverture des fichiers concerné
        file_in = open(self.get_in_file(), 'rb')
        file_out = open(self.get_out_file(), 'wb')
        encrypter = self.get_encrypter()
        file = bytes(file_in.read())
        block_size = self.get_block_size_uncrypt()
        blocks = [file[i*block_size:(i+1)*block_size] for i in range(len(file)//block_size)]
        for i in range(len(file)//block_size):
            blocks[i] = encrypter.uncrypt(blocks[i])
        # fermeture des fichiers
        out = concat_bytes(blocks)
        out = unpad(out, self.get_block_size_crypt(), style='iso7816')
        file_out.write(out)
        file_in.close()
        file_out.close()
    
    
    # getter and setters
    def set_in_file(self, in_file):
        self.__in_file = in_file
    def get_in_file(self):
        return self.__in_file
    def set_encrypter(self, encrypter):
        self.__encrypter = encrypter
    def get_encrypter(self):
        return self.__encrypter
    def set_block_size_crypt(self, block_size_crypt):
        self.__block_size_crypt = block_size_crypt
    def get_block_size_crypt(self):
        return self.__block_size_crypt
    def set_out_file(self, out_file):
        self.__out_file = out_file
    def get_out_file(self):
        return self.__out_file
    def set_block_size_uncrypt(self, block_size_uncrypt):
        self.__block_size_uncrypt = block_size_uncrypt
    def get_block_size_uncrypt(self):
        return self.__block_size_uncrypt
        
class PGMEncrypter(BlockFileEncrypter):
    """ Classe qui permet le chiffrement d'un fichier PGM
    sans affecter son entête. Pour ce faire, on compie l'entête avant le chiffrement
    
    :param in_file: le nom du fichier d'entrée
    :type in_file: string
    :param encrypter: l'objet encrypter, doit hériter de Encrypter
    :type encrypter: Encrypter
    :param block_size_crypt: le nombre d'octets d'un block à lire pour l'encryption
    :type block_size_crypt: int
    :param out_file: le nom du fichier de sortie, sa valeur par défaut est le fichier d'entrée avec l'extension .crypted
    :type out_file: string
    :param block_size_uncrypt: le nombre d'octets ecrit par un block, si différent block_size_crypt
    :type block_size_uncrypt: int"""

    def crypt_to_out(self):
        """ On suppose que notre class a bien été initialisé
        et possède les attributs file_in et file_out
        on copie les trois premières lignes du fichiers avant tout
        chiffrement"""
        # overture des fichiers
        file_in = open(self.get_in_file(), 'rb')
        file_out = open(self.get_out_file(), 'wb')

        data = b''
        for i in range(3):
            data += file_in.readline()
        file_out.write(data) # ecriture de l'entête

        # chiffrement normal
        encrypter = self.get_encrypter()
        file = bytes(file_in.read())
        block_size = self.get_block_size_crypt()
        padded_file = pad(file, block_size, style='iso7816')
        blocks = [padded_file[i*block_size:(i+1)*block_size] for i in range(len(padded_file)//block_size)]
        for block in blocks:
            crypted_block = encrypter.crypt(block)
            file_out.write(crypted_block)
        # fermeture des fichiers
        file_in.close()
        file_out.close()
        

