FROM ubuntu:20.04

ENV DEBIAN_FRONTEND="noninteractive"
ENV SNAPCRAFT_SETUP_CORE=1

RUN  apt-get update
RUN  apt-get --fix-missing install -y apt-utils

RUN  apt update; apt-get --fix-missing -y install \
                python3.8 \
                python3.8-dev \
                python3.8-venv \
                python3-pip \
                xterm \
                virt-manager \
                git \
                curl

RUN apt update; apt-get install --fix-missing -y  \
                    libgoogle-glog-* \
                    libgflags-* \
                    radare2

COPY ./sema_classifier/requirements.txt /sema-classifier/requirements.txt
RUN pip3 install -r /sema-classifier/requirements.txt

RUN apt update; apt-get --fix-missing -y install \
    cmake

COPY ./sema_classifier/docker_startup.sh /sema-classifier/docker_startup.sh
RUN chmod +x /sema-classifier/docker_startup.sh

WORKDIR /sema-classifier/application/
