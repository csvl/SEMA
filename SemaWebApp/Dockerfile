FROM ubuntu:20.04

ENV DEBIAN_FRONTEND="noninteractive"
ENV SNAPCRAFT_SETUP_CORE=1

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

         
COPY ./SemaWebApp/requirements.txt /sema-web-app/requirements.txt
WORKDIR /sema-web-app/
RUN pip3 install -r requirements.txt
RUN apt-get install graphviz -y