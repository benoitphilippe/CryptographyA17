#!/usr/bin/env python3.6
#encoding=utf-8

""" Algorithme de chiffrement asymétrique Cramer-Shoup"""

from encrypter import Encrypter
from prime import getStrongPrime, getStongGenerator
from secrets import randbelow
from hashlib import sha256
from Cryptodome.Util.number import inverse
from Cryptodome.Util.Padding import pad, unpad
from mode_encrypter import ECB
from file_encrypter import PGMEncrypter
from hasher import Hasher
import sys

class CramerShoup(Encrypter):
    
    def __init__(self):
        #super(CramerShoup,Encrypter.__init__(*args))
        pass
    
    def generate_keys(self, bit_size=512, output_filename_private="keys/key.private", output_filename_public="keys/key.public"):
        """ Génère le duo de clé privé, clé publique et enregistre le resutat"""
        
        # génération des variables
        p = getStrongPrime(bit_size)
        a1, a2 = getStongGenerator(p), getStongGenerator(p)
        x1, x2, y1, y2, w = randbelow(p), randbelow(p), randbelow(p), randbelow(p), randbelow(p)
        X = (pow(a1, x1, p) * pow(a2, x2, p)) % p
        Y = (pow(a1, y1, p) * pow(a2, y2, p)) % p
        W = pow(a1, w, p)

        # écriture des variables dans un fichier

        # clé publique
        public = open(output_filename_public, 'w')
        public.write(str(bit_size) + '\n')
        public.write(str(p) + '\n')
        public.write(str(a1) + '\n')
        public.write(str(a2) + '\n')
        public.write(str(X) + '\n')
        public.write(str(Y) + '\n')
        public.write(str(W) + '\n')
        public.close()

        # clé privé
        private = open(output_filename_private, "w")
        private.write(str(bit_size) + '\n')
        private.write(str(p) + '\n')
        private.write(str(a1) + '\n')
        private.write(str(a2) + '\n')
        private.write(str(X) + '\n')
        private.write(str(Y) + '\n')
        private.write(str(W) + '\n')
        private.write(str(x1) + '\n')
        private.write(str(x2) + '\n')
        private.write(str(y1) + '\n')
        private.write(str(y2) + '\n')
        private.write(str(w) + '\n')
        private.close()
    
    def read_key(self, file_name):
        # recupère les informations contenue dans un fichier de clés
        file = open(file_name, 'r')
        self.bit_size= int(file.readline())
        self.p = int(file.readline())
        self.a1 = int(file.readline())
        self.a2 = int(file.readline())
        self.X = int(file.readline())
        self.Y = int(file.readline())
        self.W = int(file.readline())
        test = file.readline()
        if test != '':
            self.x1 = int(test)
            self.x2 = int(file.readline())
            self.y1 = int(file.readline())
            self.y2 = int(file.readline())
            self.w = int(file.readline())
    
    def crypt(self, block):
        """ La fonction de chiffrement, à implémenter"""
        m = int.from_bytes(block, sys.byteorder)
        if m > self.p or len(block) * 8 >= self.bit_size:
            raise OverflowError('block too long')
        padded_block = pad(block, self.bit_size // 8, 'iso7816')
        bit_size = self.bit_size
        p = self.p
        a1 = self.a1
        a2 = self.a2
        W = self.W
        X = self.X
        Y = self.Y
        b = randbelow(p)

        B1 = pow(a1, b, p)
        B2 = pow(a2, b, p)
        c = (pow(W, b, p) * int.from_bytes(padded_block, sys.byteorder)) % p

        H = self.hashFunction((B1 + B2 + c) % p)
        v = (pow(X, b, p) * pow(Y, b*H, p)) % p

        # return everything to bytes
        b_B1 = B1.to_bytes(bit_size//8, sys.byteorder)
        b_B2 = B2.to_bytes(bit_size//8, sys.byteorder)
        b_c = c.to_bytes(bit_size//8, sys.byteorder)
        b_v = v.to_bytes(bit_size//8, sys.byteorder)

        return b_B1 + b_B2 + b_c + b_v
    
    def uncrypt(self, block):
        """ La fonction de déchiffrement"""

        byte_size = self.bit_size//8

        if len(block) == 4*byte_size:
            b_B1 = block[0:byte_size]
            b_B2 = block[byte_size:2*byte_size]
            b_c = block[2*byte_size:3*byte_size]
            b_v = block[3*byte_size:4*byte_size]
            
            B1 = int.from_bytes(b_B1, sys.byteorder)
            B2 = int.from_bytes(b_B2, sys.byteorder)
            c = int.from_bytes(b_c, sys.byteorder)
            v = int.from_bytes(b_v, sys.byteorder)

            # vérification de v
            p = self.p
            x1, x2, y1, y2 = self.x1, self.x2, self.y1, self.y2
            H = self.hashFunction((B1 + B2 + c) % p)
            v_bis = (pow(B1, x1, p) * pow(B2, x2, p) * pow(pow(B1, y1, p) * pow(B2, y2, p), H, p)) % p
            if v_bis != v:
                raise ValueError('Le message a été altéré après le chiffrement')
            # déchiffrement
            m = (inverse(pow(B1, self.w, p), p) * c) % p
            m = m.to_bytes(byte_size, sys.byteorder)
            return unpad(m, byte_size, 'iso7816')
        else:
            raise ValueError("Le block ne possède pas la bonne taille pour le déchiffrement")
        
    
    def set_keys(self, keys):
        """ Initialise les clés pour le chiffrement/déchiffrement 
        Les clés doivent être donnés sous forme d'un tableau
        [bit_size, p, a1, a2, X, Y, W ] pour une la clé publique
        [bit_size, p, a1, a2, X, Y, W, x1, x2, y1, y2, w] pour une clé privé
        :param keys: le tableau contenant les clés d'entiers
        :type keys: list(int)
        """
        if isinstance(keys, list):
            if all(isinstance(key, int) for key in keys):
                if len(keys) == 7:
                    self.bit_size = keys[0]
                    self.p = keys[1]
                    self.a1 = keys[2]
                    self.a2 = keys[3]
                    self.X = keys[4]
                    self.Y = keys[5]
                    self.W = keys[6]
                    return
                elif len(keys) == 12:
                    self.bit_size = keys[0]
                    self.p = keys[1]
                    self.a1 = keys[2]
                    self.a2 = keys[3]
                    self.X = keys[4]
                    self.Y = keys[5]
                    self.W = keys[6]
                    self.x1 = keys[7]
                    self.x2 = keys[8]
                    self.y1 = keys[9]
                    self.y2 = keys[10]
                    self.w = keys[11]
                    return                     
        raise ValueError("Keys must be a list of int")
    
    def get_keys(self):
        """ Accesseur pour l'attribut keys """
        return self.p.to_bytes(self.bit_size // 8, sys.byteorder)
    
    def hashFunction(self, number):
        """ Fonction de hashage d'un entier, renvoie un au autre entier issue du hashage"""
        # Pour Yacine : A implémenter comme il faut. (Il faut en reprogrammer une)
        hexe = number.to_bytes(self.bit_size//8, sys.byteorder)
        return int.from_bytes(Hasher().digest(hexe), sys.byteorder)



def main():
    cs = CramerShoup()
    # pour générer les clés : 
    # cs.generate_keys(nb_bits)
    cs.read_key("keys/key.private")
    ecb = ECB(cs)
    file = PGMEncrypter('file/lena.pgm', ecb, 512//8, 'out/lena.pgm.crypted', 1024//8)
    file.crypt_to_out()
    file = PGMEncrypter('out/lena.pgm.crypted', ecb, 512//8, 'out/lena.pgm', 4*1024//8)
    file.uncrypt_to_out()
    #word = b'another test'
    #block = cs.crypt(word)
    #word = cs.uncrypt(block)


if __name__ == '__main__':
    main()