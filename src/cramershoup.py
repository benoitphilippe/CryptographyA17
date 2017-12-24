#!/usr/bin/env python3.6
#encoding=utf-8

""" Algorithme de chiffrement asymétrique Cramer-Shoup"""

from encrypter import Encrypter
from prime import getStrongPrime, getStongGenerator
from secrets import randbelow

class CramerShoup(Encrypter):
    
    def __init__(self):
        #super(CramerShoup,Encrypter.__init__(*args))
        pass
    
    def key_generation(self, bit_size=512, output_filename_private="keys/key.private", output_filename_public="keys/key.public"):
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
        public.write(str(p) + '\n')
        public.write(str(a1) + '\n')
        public.write(str(a2) + '\n')
        public.write(str(X) + '\n')
        public.write(str(Y) + '\n')
        public.write(str(W) + '\n')
        public.close()

        # clé privé
        private = open(output_filename_private, "w")
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
    
    def key_reader(self, file_name):
        # recupère les informations contenue dans un fichier de clés
        file = open(file_name, 'r')
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
        raise NotImplementedError
    
    def uncrypt(self, block):
        """ La fonction de déchiffrement, à implémenter"""
        raise NotImplementedError
    
    def set_keys(self, keys):
        """ Initialise les clés pour le chiffrement/déchiffrement """
        raise NotImplementedError
    
    def get_keys(self):
        """ Accesseur pour l'attribut keys """
        raise NotImplementedError

def main():
    cs = CramerShoup()
    cs.key_reader("keys/key.public")

if __name__ == '__main__':
    main()