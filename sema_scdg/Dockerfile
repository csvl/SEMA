FROM ubuntu:20.04

ENV DEBIAN_FRONTEND="noninteractive"
ENV SNAPCRAFT_SETUP_CORE=1

RUN  apt-get update
RUN  apt-get --fix-missing install -y apt-utils
RUN  apt-get update
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:pypy/ppa

RUN  apt update; apt-get --fix-missing -y install \ 
                python3.8 \
                python3.8-dev \
                python3.8-venv \
                python3-pip \
                xterm \
                virt-manager \
                git \
                curl \
                pypy3 \
                python3-pip \
                python3-dev \
                libvirt-dev \
                python3.9 \
                python3.9-venv 

RUN apt-get update; apt-get --fix-missing -y install \
        pypy3-dev \
        pypy3-venv \
        python-pycparser \
        gfortran \
        cmake \
        libopenblas-dev \
        libjansson-dev \
        libssl-dev \
        libffi-dev \
        cargo \
        curl \
        build-essential

# Cuckoo
RUN apt update; apt-get --fix-missing -y install \
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
                python3-wheel 

# For Symbion
RUN apt update; apt-get install --fix-missing -y  \
                gdb-multiarch

# TCP dump for cuckoo
RUN apt update; apt-get install --fix-missing -y  \ 
                tcpdump \
                wget

# guacd for cuckoo
RUN mkdir /tmp/guac-build
RUN apt update; apt-get install --fix-missing -y  --fix-missing \ 
            libwebp-dev \
            libwebsockets-dev \
            libogg-dev \
            libvorbis-dev \
            libpulse-dev

RUN cd /tmp/guac-build; \
        wget https://www.apache.org/dist/guacamole/1.5.3/source/guacamole-server-1.5.3.tar.gz; \
        tar xvf guacamole-server-1.5.3.tar.gz && cd guacamole-server-1.5.3; \
        ./configure --with-init-dir=/etc/init.d; \
        make && make install 
RUN ldconfig
RUN /etc/init.d/guacd start


#For testing
RUN  apt update; apt-get --fix-missing -y install \ 
        libgraphviz-dev \
        pkg-config


COPY ./sema_scdg/requirements.txt /sema-scdg/requirements.txt
RUN pip3 install -r /sema-scdg/requirements.txt

COPY ./sema_scdg/requirements_pypy.txt /sema-scdg/requirements_pypy.txt
RUN pypy3 -m pip install -r /sema-scdg/requirements_pypy.txt

WORKDIR /sema-scdg/application/
