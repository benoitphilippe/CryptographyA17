#!/usr/bin/env python3.6
# encoding=utf-8

from curses import wrapper, napms  
from curses.textpad import Textbox, rectangle
from threefish import ThreeFish
from mode_encrypter import *
from file_encrypter import *
import curses
from hashlib import sha256, sha512, md5
import sys
import re

def main(stdscr):
    # selected color
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
    menu(stdscr)

def show_menu(stdscr, choice=0):
    """ affiche le menu avec la selection en surbrillance"""
    stdscr.clear()
    curses.curs_set(False)
    stdscr.addstr("*** --- Interface de chiffrement --- ***\n\n")
    if choice == 1:
        stdscr.addstr("->1<- Chiffrement symétrique avec Threefish\n", curses.color_pair(1))
    else:
        stdscr.addstr("->1<- Chiffrement symétrique avec Threefish\n")
    if choice == 2:
        stdscr.addstr("->2<- Chiffrement de Cramer-Shoup\n", curses.color_pair(1))
    else:
        stdscr.addstr("->2<- Chiffrement de Cramer-Shoup\n")
    if choice == 3:
        stdscr.addstr("->3<- Hashage d'un message\n", curses.color_pair(1))
    else:
        stdscr.addstr("->3<- Hashage d'un message\n")
    if choice == 4:
        stdscr.addstr("->4<- Déchiffrement symétrique avec Threefish\n", curses.color_pair(1))
    else:
        stdscr.addstr("->4<- Déchiffrement symétrique avec Threefish\n")
    if choice == 5:
        stdscr.addstr("->5<- Déchiffrement de Cramer-Shoup\n", curses.color_pair(1))
    else:
        stdscr.addstr("->5<- Déchiffrement de Cramer-Shoup\n")
    if  choice == 6:
        stdscr.addstr("->6<- Vérification du hash\n", curses.color_pair(1))
    else:
        stdscr.addstr("->6<- Vérification du hash\n")
    if choice == 7:
        stdscr.addstr("->q<- Pour quitter\n", curses.color_pair(1))
    else:
        stdscr.addstr("->q<- Pour quitter\n")
    stdscr.refresh()        

def menu(stdscr):
    
    loop = True
    cursor = 0

    while loop:
        show_menu(stdscr, cursor)
        loop = False
        key = stdscr.getkey()
        if key == '1':
            mode_crypt_threefish(stdscr)
        elif key == '2':
            mode_crypt_cramershoup(stdscr)
        elif key == '3':
            mode_hash(stdscr)
        elif key == '4':
            mode_uncrypt_threefish(stdscr)
        elif key == '5':
            mode_uncrypt_cramershoup(stdscr)
        elif key == '6':
            mode_hash_check(stdscr)
        elif key == 'q':
            pass
        elif key == 'KEY_DOWN':
            if cursor < 7 :
                cursor += 1
            loop = True
        elif key == 'KEY_UP':
            if cursor > 1 :
                cursor -= 1
            loop = True
        elif key == '\n':
            if cursor == 1:
                mode_crypt_threefish(stdscr)
            elif cursor == 2:
                mode_crypt_cramershoup(stdscr)
            elif cursor == 3:
                mode_hash(stdscr)
            elif cursor == 4:
                mode_uncrypt_threefish(stdscr)
            elif cursor == 5:
                mode_uncrypt_cramershoup(stdscr)
            elif cursor == 6:
                mode_hash_check(stdscr)
            elif cursor == 7:
                pass
        else:
            loop = True

def show_crypt_threeFish_instructions(stdscr, message=None, cursor=0):
    stdscr.clear()
    curses.curs_set(False)
    stdscr.addstr("*** Chiffrement avec ThreeFish ***\n\n")    

    if cursor == 1:
        stdscr.addstr("->m<- Menu\n", curses.color_pair(1))
    else:
        stdscr.addstr("->m<- Menu\n")
    if cursor == 2:
        stdscr.addstr("->q<- Quitter\n", curses.color_pair(1))
    else:
        stdscr.addstr("->q<- Quitter\n")
    if cursor == 3:
        stdscr.addstr("->i<- Saisir le nom du fichier à chiffrer/déchiffrer\n", curses.color_pair(1))
    else:
        stdscr.addstr("->i<- Saisir le nom du fichier à chiffrer/déchiffrer\n")
        
    if message is not None:
        stdscr.addstr(message)
    stdscr.refresh()
        
def mode_crypt_threefish(stdscr, message=None):

    loop = True
    cursor = 0
    while loop:
        show_crypt_threeFish_instructions(stdscr, message, cursor)
        key = stdscr.getkey()
        loop = False
        if key == 'm' or (key == '\n' and cursor == 1):
            menu(stdscr)
        elif key == 'q' or (key == '\n' and cursor == 2):
            pass
        elif key == 'KEY_UP' and cursor > 1:
            cursor -= 1
            loop = True
        elif key == 'KEY_DOWN' and cursor < 3:
            cursor += 1
            loop = True
        elif key == 'i' or (key == '\n' and cursor == 3):
            file_name = input_user(stdscr, "Veuillez saisir le nom du fichier à chiffrer. Ctrl + G pour confirmer")
            exist = True
            try:
                file = open(file_name)
                file.close()
            except IOError:
                exist = False
            if not exist:
                mode_crypt_threefish(stdscr, "\nErreur lors de l'ouverture du fichier : {}\nEssayez de nouveau\n".format(file_name))
            else:
                base_keys = input_user(stdscr, "Le fichier {} a été trouvé avec succès.\nVeuillez saisir votre clé de chiffrement. Ctrl + G pour confirmer".format(file_name))
                base_tweak = input_user(stdscr, "Maintenant, veuillez saisir votre tweak. Ctrl + G pour confirmer")
                keys = choose_keys_size(stdscr, base_keys)
                tweak = md5(base_tweak.encode()).digest()

                chiffrement_threefish(stdscr, file_name, keys, tweak)
        else:
            loop = True
            

def mode_crypt_cramershoup(stdscr):
    pass
def mode_hash(stdscr):
    pass
def mode_uncrypt_threefish(stdscr, message=None):
    loop = True
    cursor = 0
    while loop:
        show_crypt_threeFish_instructions(stdscr, message, cursor)
        key = stdscr.getkey()
        loop = False
        if key == 'm' or (key == '\n' and cursor == 1):
            menu(stdscr)
        elif key == 'q' or (key == '\n' and cursor == 2):
            pass
        elif key == 'KEY_UP' and cursor > 1:
            cursor -= 1
            loop = True
        elif key == 'KEY_DOWN' and cursor < 3:
            cursor += 1
            loop = True
        elif key == 'i' or (key == '\n' and cursor == 3):
            file_name = input_user(stdscr, "Veuillez saisir le nom du fichier à déchiffrer. Ctrl + G pour confirmer")
            exist = True
            try:
                file = open(file_name)
                file.close()
            except IOError:
                exist = False
            if not exist:
                mode_uncrypt_threefish(stdscr, "\nErreur lors de l'ouverture du fichier : {}\nEssayez de nouveau\n".format(file_name))
            else:
                base_keys = input_user(stdscr, "Le fichier {} a été trouvé avec succès.\nVeuillez saisir votre clé de chiffrement. Ctrl + G pour confirmer".format(file_name))
                base_tweak = input_user(stdscr, "Maintenant, veuillez saisir votre tweak. Ctrl + G pour confirmer")
                keys = choose_keys_size(stdscr, base_keys)
                tweak = md5(base_tweak.encode()).digest()

                dechiffrement_threefish(stdscr, file_name, keys, tweak)
        else:
            loop = True
def mode_uncrypt_cramershoup(stdscr):
    pass
def mode_hash_check(stdscr):
    pass

def chiffrement_threefish(stdscr, file_name, keys, tweak):
    mode_encrypter = choix_mode_de_chiffrement(stdscr, ThreeFish(tweak), keys)
    # on a tout ce qu'il faut pour chiffrer
    pgm = False
    if re.match('.+\.pgm.*', file_name) is not None:
        pgm = choix_mode_PGM(stdscr)
    stdscr.clear()
    stdscr.addstr("En cours de chiffrement ...\n")
    stdscr.refresh()
    file = None
    if pgm:
        file = PGMEncrypter(file_name, mode_encrypter, len(keys))
    else:
        file = BlockFileEncrypter(file_name, mode_encrypter, len(keys))
    file.crypt_to_out()
    stdscr.addstr("Votre fichier {} a été chiffré :) !".format(file_name))
    stdscr.refresh()
    napms(1000)
    menu(stdscr)

def dechiffrement_threefish(stdscr, file_name, keys, tweak):
    mode_encrypter = choix_mode_de_chiffrement(stdscr, ThreeFish(tweak), keys)
    # on a tout ce qu'il faut pour chiffrer
    pgm = False
    if re.match('.+\.pgm.*', file_name) is not None:
        pgm = choix_mode_PGM(stdscr)
    stdscr.clear()
    stdscr.addstr("En cours de déchiffrement ...\n")
    stdscr.refresh()
    file = None
    if pgm:
        file = PGMEncrypter(file_name, mode_encrypter, len(keys))
    else:
        file = BlockFileEncrypter(file_name, mode_encrypter, len(keys))
    file.uncrypt_to_out()
    stdscr.addstr("Votre fichier {} a été déchiffré :) !".format(file_name))
    stdscr.refresh()
    napms(1000)
    menu(stdscr)

def choix_mode_PGM(stdscr):
    """ laisse le choix à l'utilisateur de chiffrer en gardant la vue pgm"""
    stdscr.clear()
    stdscr.addstr("le fichier peut se chiffrer en PGM, le voulez-vous ? [O/N] :")
    stdscr.refresh()

    loop = True
    while loop:
        key = stdscr.getkey()
        loop = False
        if key == 'y' or key == 'Y' or key == 'O' or key == 'o':
            return True
        elif key == 'n' or key == 'N':
            return False
        else:
            loop = False

def show_mode_de_chiffrement(stdscr, cursor):
    stdscr.clear()
    curses.curs_set(False)
    stdscr.addstr("Veillez choisir le mode de chiffrement : \n\n")
    if cursor == 1:
        stdscr.addstr("->1<- ECB\n", curses.color_pair(1))
    else:
        stdscr.addstr("->1<- ECB\n")
    if cursor == 2:
        stdscr.addstr("->2<- CBC\n", curses.color_pair(1))
    else:
        stdscr.addstr("->2<- CBC\n")
    if cursor == 3:
        stdscr.addstr("->3<- PCBC\n", curses.color_pair(1))
    else:
        stdscr.addstr("->3<- PCBC\n")
    if cursor == 4:
        stdscr.addstr("->4<- CTR\n", curses.color_pair(1))
    else:
        stdscr.addstr("->4<- CTR\n")
    if cursor == 5:
        stdscr.addstr("->5<- OFB\n", curses.color_pair(1))
    else:
        stdscr.addstr("->5<- OFB\n")
    if cursor == 6:
        stdscr.addstr("->6<- CFB\n", curses.color_pair(1))
    else:
        stdscr.addstr("->6<- CFB\n")
    if cursor == 7:
        stdscr.addstr("->q<- Pour quitter\n", curses.color_pair(1))
    else:
        stdscr.addstr("->q<- Pour quitter\n")
    stdscr.refresh()

def choix_mode_de_chiffrement(stdscr, encrypter, keys):
    """ Laisse à l'utilisateur le choix du mode de chiffrement"""

    mode_encrypter = None

    loop = True
    cursor = 0
    while loop:
        show_mode_de_chiffrement(stdscr, cursor)
        key = stdscr.getkey()
        loop = False
        if key == '1' or (key == '\n' and cursor == 1):
            mode_encrypter = ECB(encrypter, keys)
        elif key == '2' or (key == '\n' and cursor == 2):
            mode_encrypter = CBC(encrypter, keys)
        elif key == '3' or (key == '\n' and cursor == 3):
            mode_encrypter = PCBC(encrypter, keys)
        elif key == '4' or (key == '\n' and cursor == 4):
            mode_encrypter = CTR(encrypter, keys)
        elif key == '5' or (key == '\n' and cursor == 5):
            mode_encrypter = OFB(encrypter, keys)
        elif key == '6' or (key == '\n' and cursor == 6):
            mode_encrypter = CFB(encrypter, keys)
        elif key == 'q' or (key == '\n' and cursor == 7):
            sys.exit()
        elif key == 'KEY_UP' and cursor > 1:
            cursor -= 1
            loop = True
        elif key == 'KEY_DOWN' and cursor < 7:
            cursor += 1
            loop = True
        else:
            loop = True
    
    return mode_encrypter
def show_keys_size_menu(stdscr, cursor):
    stdscr.clear()
    curses.curs_set(False)
    stdscr.addstr("Veillez choisir la taille des blocks de chiffrement : \n\n")
    if cursor == 1:
        stdscr.addstr("->1<- 256 bits\n", curses.color_pair(1))
    else:
        stdscr.addstr("->1<- 256 bits\n")
    if cursor == 2:
        stdscr.addstr("->2<- 512 bits\n", curses.color_pair(1))
    else:
        stdscr.addstr("->2<- 512 bits\n")
    if cursor == 3:
        stdscr.addstr("->3<- 1024 bits\n", curses.color_pair(1))
    else:
        stdscr.addstr("->3<- 1024 bits\n")
    if cursor == 4:
        stdscr.addstr("->q<- Pour quitter\n", curses.color_pair(1))
    else:
        stdscr.addstr("->q<- Pour quitter\n")
    stdscr.refresh()

def choose_keys_size(stdscr, base_keys):
    """ Retourne la clé hashé à la bonne taille"""

    loop = True
    cursor = 0
    while loop:
        show_keys_size_menu(stdscr, cursor)
        key = stdscr.getkey()
        loop = False    
        if key == '1' or (key == '\n' and cursor == 1):
            return sha256(base_keys.encode()).digest()
        elif key == '2' or (key == '\n' and cursor == 2):
            return sha512(base_keys.encode()).digest()
        elif key == '3' or (key == '\n' and cursor == 3):
            return sha512(base_keys.encode()).digest() + sha512(base_keys.encode()).digest()
        elif key == 'q' or (key == '\n' and cursor == 4):
            sys.exit()
        elif key == 'KEY_UP' and cursor > 1:
            cursor -= 1
            loop = True
        elif key == 'KEY_DOWN' and cursor < 4:
            cursor += 1
            loop = True
        else:
            loop = True


def input_user(stdscr, message):
    stdscr.clear()
    curses.curs_set(True)
    stdscr.addstr(message)
    editwin = curses.newwin(5, 50, 3,1)
    rectangle(stdscr, 2,0, 1+5+2, 1+50+1)
    stdscr.refresh()
    box = Textbox(editwin)
    # Let the user edit until Ctrl-G is struck.
    box.edit()
    # Get resulting contents without space and \n
    return box.gather()[:-2]

wrapper(main)