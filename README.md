DEBIN <a href="https://www.sri.inf.ethz.ch/"><img width="100" alt="portfolio_view" align="right" src="http://safeai.ethz.ch/img/sri-logo.svg"></a>
=============================================================================================================

DEBIN is a system that uses machine learning to recover debug information (e.g., names and types) of stripped binaries (x86, x64, ARM). DEBIN is developed at [SRI Lab, Department of Computer Science, ETH Zurich](https://www.sri.inf.ethz.ch/) as part of the [Machine Learning for Programming](https://www.sri.inf.ethz.ch/research/plml) project.

It is able to distinguish register-allocated and memory-allocated variables with decision-tree-based classification. Moreover, it is capable of predicting meaningful names and types for variables and functions through structured prediction with probabilistic graphical models (with [Nice2Predict](https://github.com/eth-sri/Nice2Predict)). These models are learned from thousands of non-stripped binary in open source packages. For mode details, please refer to [DEBIN CCS'18 paper](https://files.sri.inf.ethz.ch/website/papers/ccs18-debin.pdf) and [slides](https://files.sri.inf.ethz.ch/website/slides/ccs18-debin-slides.pdf).


## Setup

### Docker
We provide a docker file, which we recommend to start with. To build and run:
```
$ docker build -t debin .
$ docker run -it debin
```

### Manually

We provide scripts to setup DEBIN manually. The scripts are only tested on `Ubuntu 16.04` with `gcc 5.4.0`):
```
$ ./install_dependencies.sh  # uses apt-get and requires sudo privileges
$ ./setup.sh
```

For other platforms, please follow the steps below to setup DEBIN locally:
1. Install [Nice2Predict](https://github.com/eth-sri/Nice2Predict) (according to the instructions in the link)
2. Install [BAP](https://github.com/BinaryAnalysisPlatform/bap/) (according to the instructions in the link)
3. Install python3 dependencies:
```
$ pip3 install -r requirements.txt
```
4. Compile and install the BAP plugin that DEBIN uses:
```
$ cd ocaml
$ bapbuild -pkg yojson loc.plugin
$ bapbundle install loc.plugin
$ cd ..
```
5. Compile the shared library used to produce output:
```
$ cd cpp
$ g++ -c -fPIC modify_elf.cpp -o modify_elf.o -I./
$ g++ modify_elf.o -shared -o modify_elf.so
$ cd ..
```


## Usage 
You can run the following commands to train or test DEBIN, either in docker or locally.

### Training
To use DEBIN, one needs to train models with a list of binaries and their debug information. We provide models trained with thousands of binaries for different architectures (x86, x64 and ARM). They can be downloaded through [this link](https://files.sri.inf.ethz.ch/debin_models.tar.gz) or using the following commands:
```
$ wget https://files.sri.inf.ethz.ch/debin_models.tar.gz
$ tar -zxvf debin_models.tar.gz
$ mv crf/ models/
$ mv variable/ models/
$ rm debin_models.tar.gz
```

You can also train your own models. Here are the example commands to train the variable classification models and the CRF models using a single sample binary:
```
$ mkdir -p new_models/variable/x86
$ python3 py/train_variable.py \
          --bin_list examples/bin_list.txt \
          --bin_dir examples/stripped/ \
          --debug_dir examples/debug/ \
          --out_model new_models/variable/x86/ \
          --reg_num_f 100 \
          --off_num_f 100
$ mkdir -p new_models/crf/x86
$ python3 py/train_crf.py \
          --bin_list examples/bin_list.txt \
          --bin_dir examples/stripped/ \
          --debug_dir examples/debug/ \
          --out_model new_models/crf/x86/model \
          --n2p_train Nice2Predict/bazel-bin/n2p/training/train_json \
          --log_dir new_models/crf \
          --valid_labels c_valid_labels
```

The processes take less than a minute and the trained models are produced in `./new_models`.

### Prediction and Evaluation

First, Nice2Predict server should be run in background:
```
$ cd Nice2Predict
$ ./bazel-bin/n2p/json_server/json_server \
        --port 8604 \
        --model ../models/crf/x86/model \
        --valid_labels ../c_valid_labels \
        -logtostderr &
$ cd ..
```

To predict debug information for the example binary `lcrack`, please use the following commands:
```
$ python3 py/predict.py \
          --binary examples/stripped/lcrack \
          --output ./lcrack.output \
          --elf_modifier cpp/modify_elf.so \
          -two_pass \
          --fp_model models/variable/x86/ \
          --n2p_url http://localhost:8604
$ readelf -S lcrack.output
```
The output binary is `./lcrack.output`. You can view the section headers of the output and check the predicted debug sections by `readelf -S lcrack.output`.

To evaluate the prediction accuracy, you need the ground truth debug information as input:
```
$ python3 py/evaluate.py \
          --binary examples/stripped/lcrack \
          --debug_info examples/debug/lcrack \
          -two_pass \
          --fp_model models/variable/x86/ \
          --n2p_url http://localhost:8604 \
          --stat ./stat.txt
$ cat stat.txt
```
You can view prediction statistics in `./stat.txt`.


## Citing DEBIN
```
@inproceedings{He:2018:DPD:3243734.3243866,
 author = {He, Jingxuan and Ivanov, Pesho and Tsankov, Petar and Raychev, Veselin and Vechev, Martin},
 title = {Debin: Predicting Debug Information in Stripped Binaries},
 booktitle = {Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security},
 series = {CCS '18},
 year = {2018},
 isbn = {978-1-4503-5693-0},
 location = {Toronto, Canada},
 pages = {1667--1680},
 numpages = {14},
 url = {http://doi.acm.org/10.1145/3243734.3243866},
 doi = {10.1145/3243734.3243866},
 acmid = {3243866},
 publisher = {ACM},
 address = {New York, NY, USA},
 keywords = {binary code, debug information, machine learning, security},
} 
```

## Contributors
* [Jingxuan He](https://www.sri.inf.ethz.ch/people/jingxuan) - jingxuan.he@inf.ethz.ch
* [Pesho Ivanov](https://www.sri.inf.ethz.ch/people/pesho) - pesho@inf.ethz.ch
* [Petar Tsankov](https://www.sri.inf.ethz.ch/people/petar) - petar.tsankov@inf.ethz.ch
* [Veselin Raychev](https://www.deepcode.ai/about/) - veselin@deepcode.ai
* [Martin Vechev](https://www.sri.inf.ethz.ch/people/martin) - martin.vechev@inf.ethz.ch


## License and Copyright
* Copyright (c) 2018 [Secure, Reliable, and Intelligent Systems Lab (SRI), ETH Zurich](https://www.sri.inf.ethz.ch/)
* Licensed under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0)
