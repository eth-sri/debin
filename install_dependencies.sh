#!/bin/bash
sudo apt-get -y update

# install bazel
sudo apt-get -y install wget
wget https://github.com/bazelbuild/bazel/releases/download/0.19.2/bazel-0.19.2-linux-x86_64
sudo mv bazel-0.19.2-linux-x86_64 /usr/local/bin/bazel
sudo chmod +x /usr/local/bin/bazel

# Nice2Predict dependencies
sudo apt-get install -y git libmicrohttpd-dev libcurl4-openssl-dev libgoogle-glog-dev libgflags-dev

# BAP dependencies
sudo apt-get install -y build-essential libx11-dev pkg-config opam binutils-multiarch clang debianutils libgmp-dev libzip-dev llvm-3.8-dev m4 perl zlib1g-dev

# python dependencies
sudo apt-get install -y python3 python3-pip
pip3 install -r requirements.txt
