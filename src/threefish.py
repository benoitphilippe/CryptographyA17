#!bin/python3
#encoding=utf-8

""" L'algorithme de chiffrement symétrique threefish """

from encrypter import Encrypter
from file_input_output import xorBytes
from bitfield import bitfield, bitfield_to_int
from mode_encrypter import CBC
from file_input_output import PGMEncrypter
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
     

class ThreeFish(Encrypter):
    """ La classe qui définit le chiffrement ThreeFish"""

    def __init__(self, tweak=None, keys=None):
        """ Initialise la classe avec :
        
        :param keys: une clé de 256, 512 ou 1024 bits
        :type keys: bytes
        :param tweak: un tweak de 128 bits
        :type tweak: bytes"""

        if tweak is not None:
            self.set_tweak(tweak)
        if keys is not None:
            self.set_keys(keys)
    
    def set_tweak(self, tweak):
        """ set l'attribut tweak
        
        :param tweak: un block de 128 bits
        :type tweak: bytes"""
        if isinstance(tweak, bytes): # tweak est du type bytes
            if len(tweak) * 8 == 128: # tweak est de 128 bits
                self.__tweak = tweak
                return
        # sinon, on lance un erreur
        raise TypeError('tweak must be 16 bytes length')
    
    def get_tweak(self):
        """ accesseur de tweak"""
        return self.__tweak
    
    def set_block_size(self, block_size):
        """ Sauvegarde la taille d'un block en bits
        
        :param block_size: la taille du block/ de la clé en bits
        :type block_size: int"""
        if block_size in [256, 512, 1024]:
            self.__block_size = block_size
        else:
            raise "block_size must be in [256, 512, 1024]"
    
    def get_block_size(self):
        """ Accesseur de block_size
        
        :return: la taille d'un block à traiter en bits
        :rtype: int """
        return self.__block_size
    
    def set_keys(self, keys):
        """ Initialisations des clés pour le chiffrement/déchiffrement,
        une clée doit être une suite de bytes de longeur 256, 512 ou 1024 bits
        
        :param keys: la clé pour le chiffrement
        :type keys: bytes"""

        # keys doit être du type bytes
        if isinstance(keys, bytes):
            # vérifie et sauvegarde la taille de keys
            self.set_block_size(len(keys)*8)
            # on évalue N
            N = self.get_block_size() // 64 # ici notre N vaut 4, 8 ou 16
            # on affecte les valeurs à K
            K = []
            for i in range(N): # découpage de keys en N mots
                K.append(keys[(i*(64//8)):((i+1)*(64//8))])
            # on ajoute le dernier mot
            C = b'1bd11bdaa9fc1a22'
            K.append(C)
            for i in range(N): # on apllique le xor sur tout les mots
                K[N] = xorBytes(K[N], K[i])
            # On calcul les tweaks
            tweak = self.get_tweak()
            t = [ tweak[0:8], tweak[8:16], xorBytes(tweak[0:8], tweak[8:16]) ]
            # On détemine les sous-clés k
            k = []
            for s in range(20): # s in [0;19]
                k.append([])
                for i in range(N): # i in [0:N-1]
                    step_key = K[(i + s)%(N + 1)]
                    if  i <= N - 4: # on prend directment une sous-clé sans modification
                        ki = step_key
                    elif i == N - 3: # on additionne avec un tweak
                        int_tweak = int.from_bytes(t[s%3], sys.byteorder)
                        int_Key = int.from_bytes(step_key, sys.byteorder)
                        ki = (int_Key + int_tweak) % pow(2,64)
                        # convert back to bytes
                        ki = ki.to_bytes(64//8, sys.byteorder)
                    elif i == N - 2: # même chose mais avec un autre tweak
                        int_tweak = int.from_bytes(t[(s+1)%3], sys.byteorder)
                        int_Key = int.from_bytes(step_key, sys.byteorder)
                        ki = (int_Key + int_tweak) % pow(2,64)
                        # convert back to bytes
                        ki = ki.to_bytes(64//8, sys.byteorder)
                    elif i == N - 1: # on additionne directement avec s
                        int_Key = int.from_bytes(step_key, sys.byteorder)
                        ki = (int_Key + s) % pow(2,64)
                        # convert back to bytes
                        ki = ki.to_bytes(64//8, sys.byteorder)
                    else :
                        raise OverflowError('i gets > N')
                    k[s].append(ki)
        else:
            raise TypeError("keys must be bytes type")
        self.__keys = k
        self.__initial_key = keys
    
    def get_keys(self):
        """ Accesseurs de la clé donnée initialement """
        return self.__initial_key
    
    def get_tab_keys(self):
        """ Accesseur de keys sous forme de tableau"""
        return self.__keys

    def mix(self, word1, word2):
        """ Fonction de mixage, prend deux mots de 64 bits,
        en résultat, on obtient deux mots de 64 bits
        
        :param word1: un mot de 64 bits
        :param word2: un mot de 64 bits
        :type word1: bytes
        :type word2: bytes
        :return: deux mots de 64 bits
        :rtype: (bytes, bytes)"""

        # premièrement, on convertit nos mots en int
        w1 = int.from_bytes(word1, sys.byteorder)
        w2 = int.from_bytes(word2, sys.byteorder)

        # on calcul c1
        c1 = (w1 + w2) % pow(2, 64)

        # on calcul c2
        # dans notre cas, on effectue des rotations circulaires grâce à
        # la valeur de tweak modulo 64
        R = int.from_bytes(self.get_tweak(), sys.byteorder) % 64
        cycled = rol(w2, R, 64)

        c2 = c1 ^ cycled

        # on converti en bytes
        c1 = c1.to_bytes(64//8, sys.byteorder)
        c2 = c2.to_bytes(64//8, sys.byteorder)

        return c1, c2

    def inv_mix(self, c1, c2):
        """ Retrouve les mots d'origine en fonction de c1 et c2,
        les mots mixés par la methode __mix()
        
        :param c1: le premier mot mixé de 64 bits
        :param c2: le deuxième mot mixé de 64 bits
        :type c1: bytes
        :type c2: bytes
        :return: les deux mots d'origines
        :rtype: (bytes, bytes)"""

        # conversion des mixés en int
        int_c1 = int.from_bytes(c1, sys.byteorder)
        int_c2 = int.from_bytes(c2, sys.byteorder)

        # on retrouve cycled
        cycled = int_c1 ^ int_c2

        # on retrouve R
        R = int.from_bytes(self.get_tweak(), sys.byteorder) % 64

        # on en déduit w2
        w2 = ror(cycled, R, 64)

        # on retrouve w1
        w1 = (int_c1 - w2) % pow(2,64)

        # conversion en bytes
        word1 = w1.to_bytes(64//8, sys.byteorder)
        word2 = w2.to_bytes(64//8, sys.byteorder)

        return word1, word2

    def permutation(self, blocks):
        """ Effectue un permutation sur un tableau de blocks
        :param blocks: un tableau de blocks de 64 bits de taille 4, 8, ou 16
        :param blocks: list(bytes)
        :return: un tableau du même nombre de blocks de 64 bits
        :rtype: list(bytes)"""

        # premièrement on calcul N
        N = self.get_block_size()//64

        if isinstance(blocks, list) and len(blocks) == N:
            if all( isinstance(block, bytes) for block in blocks) and all(len(block)==8 for block in blocks) :
                # on effectue la permutation
                P = blocks
                # rotation du tableau à droite
                P = P[-1:] + P[:-1]
                # chaque mot est permuté sur lui même
                result = []
                for block in P:
                    result.append(self.permutation_64bits(block))
                return result
        raise TypeError('wrong argument, blocks must be a list of bytes')
    
    def permutation_inv(self, blocks):
        """ Effectue la permutation_inv sur un tableau de blocks
        :param blocks: un tableau de blocks de 64 bits de taille 4, 8, ou 16
        :param blocks: list(bytes)
        :return: un tableau du même nombre de blocks de 64 bits
        :rtype: list(bytes)"""

        # premièrement on calcul N
        N = self.get_block_size()//64

        if isinstance(blocks, list) and len(blocks) == N:
            if all( isinstance(block, bytes) for block in blocks) and all(len(block)==8 for block in blocks) :
                # on inverse la permutation sur chaque mots
                P = []
                for block in blocks:
                    P.append(self.permutation_inverse_64bits(block))
                # rotation du tableau à gauche
                P = P[1:] + P[:1]
                # on retourne le résultat
                return P

        raise TypeError('wrong argument, blocks must be a list of bytes')
        

    def permutation_64bits(self, block64bits):
        """ Permutation fonction

        :param block64bits: a 64 bits block to permute
        :type block64bits: bytes
        :return: a 64 bits blocks permuted
        :rtype: bytes """
        #Définition de la permutation
        PI = [57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35,
              27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63,
              55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16,
              8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44,
              36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6]
        
        if len(block64bits) == 64//8:
            int_block = int.from_bytes(block64bits, byteorder=sys.byteorder)
            bitarray = bitfield(int_block, length=64)
            bitarray_permuted = []
            for i in range(64):
                # on parcour les 64 bits, à chaque position, on effectue une permutation
                bitarray_permuted.append(bitarray[PI[i]])
            
            int_block_permuted = bitfield_to_int(bitarray_permuted)
            return int_block_permuted.to_bytes(64//8, sys.byteorder)
        else:
            raise "block64bits must be 64 bits length"
                

    def permutation_inverse_64bits(self, block64bits):
        """ Perutation inverse

        :param block64bits: un block de 64 bits à permuter
        :type block64bits: bytes
        :return: le block de 64 bits associer avec la permutation
        :rtype: bytes """
        #Définition de la permutation inverse
        PInv = [39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46,
                 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21,
                 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35,
                 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10,
                 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57,
                 25, 32, 0, 40, 8, 48, 16, 56, 24]
        if len(block64bits) == 64//8:
            int_block = int.from_bytes(block64bits, byteorder=sys.byteorder)
            bitarray = bitfield(int_block, length=64)
            bitarray_permuted = []

            for i in range(64):
                bitarray_permuted.append(bitarray[PInv[i]])
            
            int_block_permuted = bitfield_to_int(bitarray_permuted)
            return int_block_permuted.to_bytes(64//8, sys.byteorder)
    
    def crypt(self, block):
        """ Chiffre un block de données, ce block doit être de la même taille que la clé
        :param block: le block à chiffrer
        :type block: bytes
        :return: le block chiffré
        :rtype: bytes"""

        b = block
        N = self.get_block_size() // 64

        # il y a 76 tournées
        for d in range(76):
            if d % 4 == 0:
                # toute les 4 tournées, on additionne le block et une sous-clé
                b = add_bytes(b, concat_bytes(self.get_tab_keys()[d//4]), self.get_block_size()//8)
            
            # mixage et permutation
            b = split_to_word(b, 64//8)
            for i in range(0,N,2):
                b[i], b[i+1] = self.mix(b[i], b[i+1])
            b = self.permutation(b)
            b = concat_bytes(b)

        # dernière addition de sous-clé
        b = add_bytes(b, concat_bytes(self.get_tab_keys()[-1]), self.get_block_size()//8)
        return b    
    
    def uncrypt(self, block):
        """ Déchiffre un block de données, ce block doit être de la même taille que la clé
        :param block: le block à chiffrer
        :type block: bytes
        :return: le block chiffré
        :rtype: bytes"""

        b = block
        N = self.get_block_size() // 64

        # il y a 76 tournées
        for d in range(76, 0, -1):
            if d % 4 == 0:
                # toute les 4 tournées, on soustraie le block et une sous-clé
                b = sub_bytes(b, concat_bytes(self.get_tab_keys()[(d//4)]), self.get_block_size()//8)
            # permutation et mixage
            b = split_to_word(b, 64//8)
            b = self.permutation_inv(b)
            for i in range(0,N,2):
                b[i], b[i+1] = self.inv_mix(b[i], b[i+1])
            b = concat_bytes(b)

        # dernière soustraction de sous-clé
        b = sub_bytes(b, concat_bytes(self.get_tab_keys()[0]), self.get_block_size()//8)
        return b

def main():
    key = b'Ce doit etre une cle de 256 bits' # ou 512 ou 1024
    tweak = b'un twEAK de 128b'
    tf = ThreeFish(keys=key, tweak=tweak)
    # blocks = b'12345678123456781234567812345678'
    cbc = CBC(tf, key)
    file = PGMEncrypter('lena.pgm', cbc, 256//8, 'out/lena.crypted.pgm')
    file.crypt_to_out()
    file = PGMEncrypter('out/lena.crypted.pgm', cbc, 256//8, 'out/lena.uncrypted.pgm')
    file.uncrypt_to_out()

if __name__ == '__main__':
    main()