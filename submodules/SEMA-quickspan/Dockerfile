FROM ubuntu:xenial
RUN apt-get update && apt-get install -y -qq libgflags-* libgoogle-glog-* cmake git build-essential 
ADD . /cpp_gspan/
RUN cd /cpp_gspan && mkdir -p build && cd build && rm -rf * && cmake .. && make && cp gspan /usr/bin/
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
WORKDIR /cpp_gspan
CMD /bin/bash 
