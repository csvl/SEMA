FROM ubuntu:20.04

ENV DEBIAN_FRONTEND="noninteractive"
ENV SNAPCRAFT_SETUP_CORE=1

RUN  apt-get update
RUN  apt-get --fix-missing install apt-utils
RUN  apt-get update
RUN  apt update; apt-get --fix-missing -y install \ 
                python3.8 \
                python3.8-dev \
                python3.8-venv \
                python3-pip \
                xterm \
                virt-manager \
                git \
                curl

# Cuckoo
RUN apt update; apt-get --fix-missing -y install \
                libffi-dev \
                libssl-dev \
                libjpeg-dev \
                zlib1g-dev \
                swig \
                qemu-kvm \
                libvirt-daemon-system \
                libvirt-clients \
                bridge-utils \
                python3-libvirt \
                tcpdump \
                apparmor-utils \
                libcap2-bin \
                libcairo2-dev \
                libjpeg-turbo8-dev \
                libpng-dev \
                libossp-uuid-dev \
                freerdp2-dev \
                libvirt-dev \
                python3-wheel 

# For Symbion
RUN apt update; apt-get install --fix-missing -y  \
                gdb-multiarch

# TCP dump for cuckoo
RUN apt update; apt-get install --fix-missing -y  \ 
                tcpdump \
                wget \
                software-properties-common

# guacd for cuckoo
RUN mkdir /tmp/guac-build
RUN apt update; apt-get install --fix-missing -y  --fix-missing \ 
            libwebp-dev \
            libwebsockets-dev \
            libogg-dev \
            libvorbis-dev \
            libpulse-dev

RUN cd /tmp/guac-build; \
        wget https://www.apache.org/dist/guacamole/1.5.2/source/guacamole-server-1.5.2.tar.gz; \
        tar xvf guacamole-server-1.5.2.tar.gz && cd guacamole-server-1.5.2; \
        ./configure --with-init-dir=/etc/init.d; \
        make && make install 
RUN ldconfig
RUN /etc/init.d/guacd start


COPY ./SemaSCDG/requirements.txt /sema-scdg/requirements.txt
RUN pip3 install -r /sema-scdg/requirements.txt

# Angr-utils for cfg
# RUN cd /sema-scdg/application/submodules/bingraphvis; pip install .
# RUN cd /sema-scdg/application/submodules/angr-utils;  pip install .

WORKDIR /sema-scdg/application/
