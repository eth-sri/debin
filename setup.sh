#!/bin/bash
# Nice2Predict
git clone https://github.com/eth-sri/Nice2Predict.git
cd Nice2Predict
bazel build //...
cd ..

# BAP
opam init --auto-setup --comp=4.05.0 --yes
opam install depext --yes
opam depext --install bap=1.4.0 --yes
opam install yojson --yes

# build bap plugin
cd ./ocaml
rm -r _build loc.plugin
opam config exec -- bapbuild -pkg yojson loc.plugin
opam config exec -- bapbundle install loc.plugin
cd ../

# compile shared library for producing output binary
cd ./cpp
g++ -c -fPIC modify_elf.cpp -o modify_elf.o -I./
g++ modify_elf.o -shared -o modify_elf.so
cd ../

echo "eval `opam config env`" >> ~/.bashrc
source ~/.bashrc