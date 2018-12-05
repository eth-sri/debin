FROM ubuntu:16.04

RUN apt-get -y update

# install bazel
RUN apt-get -y install wget
RUN wget https://github.com/bazelbuild/bazel/releases/download/0.19.2/bazel-0.19.2-linux-x86_64
RUN mv bazel-0.19.2-linux-x86_64 /usr/local/bin/bazel
RUN chmod +x /usr/local/bin/bazel

# install Nice2Predict
WORKDIR /debin
RUN apt-get install -y \
    git \
    libmicrohttpd-dev \
    libcurl4-openssl-dev \
    libgoogle-glog-dev \
    libgflags-dev

RUN git clone https://github.com/eth-sri/Nice2Predict.git
RUN cd Nice2Predict && \
    bazel build //... && \
    cd ..

# install BAP
RUN apt-get -y install \
    build-essential \
    libx11-dev \
    m4 \
    pkg-config \
    python-pip \
    sudo \
    unzip \
    wget \
    opam
RUN opam init --auto-setup --comp=4.05.0 --yes
RUN opam depext --install bap=1.4.0 --yes
RUN opam install yojson --yes

# copy debin
ADD ./ocaml /debin/ocaml
ADD ./cpp /debin/cpp
ADD ./py /debin/py
ADD ./c_valid_labels /debin/c_valid_labels
ADD ./requirements.txt /debin/requirements.txt

WORKDIR /debin

# install python dependencies
RUN apt-get -y install \
    python3 \
    python3-pip
RUN pip3 install -r requirements.txt

# build bap plugin
WORKDIR /debin/ocaml
RUN rm -rf ocaml/_build loc.plugin && \
    opam config exec -- bapbuild -pkg yojson loc.plugin && \
    opam config exec -- bapbundle install loc.plugin

# compile shared library for producing output binary
WORKDIR /debin/cpp
RUN g++ -c -fPIC modify_elf.cpp -o modify_elf.o -I./ && \
    g++ modify_elf.o -shared -o modify_elf.so

RUN echo "eval `opam config env`" >> /etc/bash.bashrc

ADD ./examples /debin/examples
ADD ./models /debin/models

WORKDIR /debin

ENTRYPOINT [ "/bin/bash" ]