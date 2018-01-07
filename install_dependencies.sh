#!/bin/bash

# install python3.6
sudo apt-get install python3.6 python3.6-dev libssl-dev

# install pip3.6
sudo python3.6 install-pip.py

# install all dependencies with pip
sudo pip install -r requirements.txt
