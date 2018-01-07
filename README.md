# CryptographyA17

Projet de cryptographie UTT Automne 2017. Chaque option guide l'utilsateur pour fournir les éléments nécessaires au chiffrement ou au déchiffrement. Lorsque le programme est lancé, il guide l'utilisateur pour effectuer :
- 1 : Le chiffrement avec ThreeFish d'un fichier.
- 2 : Le chiffrement avec CramerShoup d'un fichier.
- 3 : Le hashage d'un fichier.
- 4 : Le déchiffrement avec Threefish d'un fichier.
- 5 : Le déchiffrement avec CramerShoup d'un fichier.
- 6 : La vérification d'un hash

## Pour Commencer
Le projet est fourni avec un environnement python qui nécessite des dépendances. Afin de faciliter son lancement, des racourcis d'execution et d'instalation ont été mis à disposition.

### Instalation
Si vous essayer de lancer le programme sous un environnement linux/Ubuntu, un script d'instalation des dépendences est fourni [install_dependencies.sh]. Dans le cas contraire, il vous faudra :

- installer les paquets python3.6, python3.6-dev et libssl-dev
- installer pip3.6
- se servir de pip3.6 pour télécharger les dépendances décrites dans [requirements.txt]

pour l'instalation de pip, vous pouvez vous servir du script install-pip.py

```
sudo python3.6 install-pip.py
```

Une fois python3.6 et pip3.6 installés, vous pouvez utiliser la commande :

```
sudo pip3.6 install -r requirements.txt
```
pour installer toutes les dépendances en une fois

### Exécution

Pour lancer le programme sous linux une fois les dépendances installées :
```
./launch.sh
```

Si il vous est impossible de lancer le script pour une quelconque raison. Sachez que le programme peut se lancer directement avec l'interpreteur python :
```
python3.6 src/scr.py
```

### Problèmes connus
Si l'instalation depuis pip échoue, il est possible de télécherger les version antérieurs à celle données dans requirements.txt. Pour cela, il suffit de retirer leur numéro de version.

```
distro-info===0.14build1
pygobject==3.22.0
python-apt==1.4.0b2
```
devient 
```
distro-info
pygobject
python-apt
```
