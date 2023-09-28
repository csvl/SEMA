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

## Install mongodb
sudo apt-get -y install mongodb

## Install PostgreSQL
sudo apt-get install -y postgresql libpq-dev

sudo apt-get install -y gdb-multiarch

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
printf '\n%s\n' "=============> Install cuckoo: =============>"

# Install cuckoo
virtualenv -p /usr/bin/python2.7 penv-2.7
source penv-2.7/bin/activate
cd $ROOTPATH/src/submodules/toolchain_cuckoo
ls
pip2 install -U distorm3
python2 stuff/monitor.py
pip2 install .
# create .cwd file in dist/cuckoo/private with .git/HEAD inside
sudo apt-get install mingw-w64 make flex bison texinfo
# create db

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

printf '\n%s\n' "-------------> Install malware volatility: <-------------"

# Install volatility
cd $ROOTPATH/src/submodules/volatility
pip2 install .

deactivate

printf '\n%s\n' "-------------> Install malware custom_unipacker: <-------------"

cd $ROOTPATH/
source penv/bin/activate
# Install custom_unipacker
cd $ROOTPATH/src/submodules/unipacker-custom
if [ $PYPY = true ]; then
    pypy3 -m pip install .
fi
python3 -m pip install .
deactivate

cd $ROOTPATH/

printf '\n%s\n' "-------------> Install GSPAN: <-------------"

cd $ROOTPATH/src/submodules/SEMA-quickspan
mkdir build && cd build
cmake ..
make

cd $ROOTPATH/
