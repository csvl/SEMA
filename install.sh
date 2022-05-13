#!/bin/sh

MALDB=true
VMS=false
VMI=false
CUDA=false
PYPY=false


for i in "$@"; do
  case $i in
    --no_malware_db)
      MALDB=false
      shift # past argument with no value
      ;;
    --vms_install)
      VMI=true
      shift 
      ;;
    --vms_dl)
      VMS=true
      shift 
      ;;
    --pypy)
      PYPY=true
      shift 
      ;;
    --pytorch_cuda)
      CUDA=true
      shift 
      ;;
    *)
      # unknown option
      ;;
  esac
done
echo "VMS    = ${VMS}"
echo "VMI    = ${VMI}"
echo "MALDB  = ${MALDB}"
echo "PYPY  = ${PYPY}"
echo "CUDA  = ${CUDA}"

ROOTPATH=$PWD
echo "Root path of the project is " ${ROOTPATH}

printf '\n%s\n' "=============> Install packages: =============>"

# Toolchain
sudo apt-get --fix-missing -y install python3.8 python3.8-dev
sudo apt-get --fix-missing -y install python3.8-venv
sudo apt-get --fix-missing -y install python3-pip xterm
sudo apt-get --fix-missing -y install virt-manager

# Cuckoo deps
sudo apt-get --fix-missing -y install python python-pip python-dev libffi-dev libssl-dev
sudo apt-get --fix-missing -y install python-virtualenv python-setuptools
sudo apt-get --fix-missing -y install libjpeg-dev zlib1g-dev swig

sudo apt-get --fix-missing -y install qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils python-libvirt
sudo apt-get --fix-missing -y install tcpdump apparmor-utils 
sudo apt-get --fix-missing -y install libcap2-bin

sudo apt-get --fix-missing -y install libcairo2-dev libjpeg-turbo8-dev libpng-dev libossp-uuid-dev libfreerdp-dev
sudo apt-get --fix-missing -y install libvirt-dev python3-wheel 
#FL
sudo apt install rabbitmq-server
sudo apt-get install zip

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

sudo apt remove --purge cmake
sudo apt install snapd
sudo snap install cmake --classic

## Install mongodb
sudo apt-get -y install mongodb

## Install PostgreSQL
sudo apt-get install -y postgresql libpq-dev

sudo apt-get install -y gdb-multiarch

if [ $PYPY = true ]; then
    # ln -s /usr/lib/x86_64-linux-gnu/libyara.so.3 /usr/lib/pypy3/lib/libyara.so
    sudo apt-get update
    sudo apt-get install libc6 
    sudo add-apt-repository ppa:pypy/ppa
    sudo apt update
    sudo apt install pypy3 pypy3-dev
    #sudo snap install pypy3 --classic
    sudo apt-get install g++
    sudo apt-get install libatlas-base-dev
fi

# gspan
sudo apt-get install libgoogle-glog-*
sudo apt-get install libgflags-*
sudo apt-get install radare2

git submodule update --init --recursive
git submodule update --recursive

printf '\n%s\n' "=============> Install toolchain: =============>"

# Install ToolChain
python3.8 -m venv penv
source penv/bin/activate
pip install --upgrade pip
pip3 install wheel
pip3 install setuptools_rust
pip3 install .

if [ $CUDA = true ]; then
  # CUDA core 
  wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/cuda-ubuntu2004.pin
  sudo mv cuda-ubuntu2004.pin /etc/apt/preferences.d/cuda-repository-pin-600
  sudo apt-key adv --fetch-keys https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/7fa2af80.pub
  sudo add-apt-repository "deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/ /"
  sudo apt-get update
  sudo apt-get -y install cuda
fi

if [ $PYPY = true ]; then
    # your standard pip install folder could caused problems
    pypy3 -m ensurepip
    pypy3 -m pip install --upgrade pip testresources setuptools wheel
    pypy3 -m pip install setuptools_rust
    pypy3 -m pip install numpy pandas
    pypy3 -m pip install pybind11 avatar2
    pypy3 -m pip install yara-python # yara
    pypy3 -m pip install sklearn 
    pypy3 -m pip install matplotlib
    pypy3 -m pip install grakel
    pypy3 -m pip install seaborn 
    #pypy3 -m pip install ft2font
    pypy3 -m pip install  . 
    sudo apt-get install libjansson-dev
    pypy3 -m pip install unicorn
    pypy3 -m pip install grakel
    pypy3 -m pip install gensim
    #pypy3 -m pip install torch
    pypy3 -m pip install --global-option="build" --global-option="--enable-cuckoo" --global-option="--enable-magic" yara-python
    #pypy3 -m pip install --global-option="build"  yara 

    # TODO
    cd /tmp/ 
    pypy3 -m pip install yara-python==3.11.0 -t . #yara
    sudo mkdir /usr/lib/pypy3/lib
    sudo cp usr/lib/pypy3/lib/libyara.so /usr/lib/pypy3/lib/libyara.so
    sudo cp $ROOTPATH/penv/lib/python3.8/site-packages/angr/lib/angr_native.so /home/crochetch/.local/lib/pypy3.7/site-packages/angr/lib/angr_native.so #/usr/lib/pypy3/lib/angr_native.so

    cd $ROOTPATH
    # pypy3 -m pip install  libvirt-python # TODO error when installing pypy with snap
    # # https://github.com/paramiko/paramiko/issues/1435
    # pypy3 -m pip uninstall paramiko
    # pypy3 -m pip uninstall PyNaCl
    # PARAMIKO_REPLACE=1 pypy3 -m pip install https://github.com/ploxiln/paramiko-ng/archive/2.7.2.tar.gz#egg=paramiko
fi

deactivate

if [ $MALDB = true ]; then
    printf '\n%s\n' "-------------> Install malware database: <-------------"
    ## Unzip database
    cd $ROOTPATH/src/databases/
    bash extract_deploy_db.sh
    cd $ROOTPATH/
fi


printf '\n%s\n' "=============> Install angr-target: =============>"

source penv/bin/activate
cd $ROOTPATH/src/submodules/angr-targets/
if [ $PYPY = true ]; then
    pypy3 -m pip install nose
    pypy3 -m pip install .
fi
pip3 install nose
pip3 install .
deactivate
cd $ROOTPATH/

# install fix for federated learning with celery (bug due to encoding argument of sys.stdout and ProxyLogger)
rm penv/lib/python3.8/site-packages/z3/z3core.py
cp penv-fix/z3/z3core.py penv/lib/python3.8/site-packages/z3/z3core.py

printf '\n%s\n' "-------------> Install tcpdump: <-------------"


## Installing tcpdump
sudo aa-disable /usr/sbin/tcpdump
sudo groupadd pcap
sudo usermod -a -G pcap $USER
sudo chgrp pcap /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump

printf '\n%s\n' "-------------> Install malware guacd: <-------------"

## install guac
mkdir /tmp/guac-build
cd /tmp/guac-build
wget https://www.apache.org/dist/guacamole/1.3.0/source/guacamole-server-1.3.0.tar.gz
tar xvf guacamole-server-1.3.0.tar.gz && cd guacamole-server-1.3.0
./configure --with-init-dir=/etc/init.d
make && sudo make install && cd ..
sudo ldconfig
sudo /etc/init.d/guacd start

if [ $VMS = true ]; then
    printf '\n%s\n' "-------------> Download vms database: <-------------"
    cd $ROOTPATH/src/ToolChainSCDG/sandboxes/toolchain_sandbox_images/
    wget "https://uclouvain-my.sharepoint.com/:u:/g/personal/christophe_crochet_uclouvain_be/ETxNbh8gN8ZDi_NSVV3WhxIBEVECn0YiSf-0Z9Ur6B-Utg?download=1" -O win7_x64_cuckoo.zip 
    wget "https://uclouvain-my.sharepoint.com/:u:/g/personal/christophe_crochet_uclouvain_be/EbgBGWhZqDtPt64cKxn5-2wBIu97kENuXLBqNpDvS9DCvg?download=1" -O ubuntu18.04_cuckoo.zip
fi
if [ $VMI = true ] && [$VMS = true]; then
    printf '\n%s\n' "-------------> Install vms database: <-------------"
    ## Unzip vms
    bash unzip.sh
    cd $ROOTPATH/
fi

printf '\n%s\n' "-------------> Install malware volatility: <-------------"

# Install volatility
cd $ROOTPATH/src/submodules/volatility
pip2 install .

deactivate

cd $ROOTPATH/

printf '\n%s\n' "-------------> Install GSPAN: <-------------"

cd $ROOTPATH/src/submodules/SEMA-quickspan
mkdir build && cd build
cmake ..
make

cd $ROOTPATH/
