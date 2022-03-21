#!/bin/bash

apt update
apt-get install python3-pip

apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

pip3 install graphviz
pip3 install monkeyhex
pip3 install angr

