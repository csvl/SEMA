FROM ubuntu:20.04

ENV DEBIAN_FRONTEND="noninteractive"
ENV SNAPCRAFT_SETUP_CORE=1

RUN  apt-get update
RUN  apt-get --fix-missing install -y apt-utils
RUN  apt-get update
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:pypy/ppa
RUN add-apt-repository ppa:deadsnakes/ppa

RUN  apt update; apt-get --fix-missing -y install \
                python3.9 \
                python3.9-dev \
                python3.9-venv \
                python3.9-distutils \
                xterm \
                virt-manager \
                git \
                curl \
                libvirt-dev 


RUN apt-get update; apt-get --fix-missing -y install \
        python-pycparser \
        gfortran \
        cmake \
        libopenblas-dev \
        libjansson-dev \
        libssl-dev \
        libffi-dev \
        cargo \
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

RUN apt-get --fix-missing -y install radare2


ENV PYENV_ROOT /root/.pyenv
ENV PATH $PYENV_ROOT/shims:$PYENV_ROOT/bin:$PATH
# Install pyenv
RUN set -ex \
    && curl https://pyenv.run | bash \
    && pyenv update 

RUN apt-get install -y libbz2-dev

# Pip
# RUN wget https://bootstrap.pypa.io/get-pip.py 
RUN pyenv install 3.8.10; pyenv local 3.8.10
COPY ./sema_scdg/requirements.txt /sema-scdg/requirements.txt
RUN pip install -r /sema-scdg/requirements.txt --default-timeout=100

#pypy
# GCC problem
# RUN wget https://downloads.python.org/pypy/pypy3.9-v7.3.16-linux64.tar.bz2
# RUN apt install gcc make libffi-dev pkg-config zlib1g-dev libbz2-dev \
#         libsqlite3-dev libncurses5-dev libexpat1-dev libssl-dev libgdbm-dev \
#         tk-dev libgc-dev python-cffi \
#         liblzma-dev libncursesw5-dev; 
# RUN git clone https://github.com/pypy/pypy.git; cd pypy; \
#         git checkout a2113ea87262a302918df8a262fb073f81776bbe; \
#         python3.9 -mpip install cffi; \
#         python3.9 pypy/tool/release/package.py --archive-name=pypy3.9-v7.3.16-linux64; \
#         tar xf pypy3.9-v7.3.16-linux64.tar.bz2 -C /opt; \
#         ln -s /opt/pypy3.9-v7.3.16-linux64/bin/pypy /usr/local/bin/pypy 

# # Ensure the pypy binary is available in the PATH
# ENV PATH="/opt/pypy3.9-v7.3.16-linux64/bin:$PATH"
RUN pyenv install pypy3.9-7.3.16; pyenv local pypy3.9-7.3.16
COPY ./sema_scdg/requirements_pypy.txt /sema-scdg/requirements_pypy.txt
RUN pip install -r /sema-scdg/requirements_pypy.txt --default-timeout=100 


# TODO
# RUN pypy -m pip uninstall capstone;  pypy -m pip install capstone

COPY ./sema_scdg/ /sema-scdg
COPY ./submodules/angr-utils /sema-scdg/application/submodules/angr-utils
COPY ./submodules/bingraphvis /sema-scdg/application/submodules/bingraphvis
# TODO not used for now <!>
COPY ./penv-fix/ /sema-scdg/application/penv-fix 
COPY ./database/ /sema-scdg/application/database

WORKDIR /sema-scdg/application/
