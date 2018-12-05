## DEBIN models

Please run [`train_variable.py`](../py/train_variable.py) and [`train_crf.py`](../py/train_crf.py) to train models with a list of binaries.

We also provide trained models which can be downloaded through [this link](https://files.sri.inf.ethz.ch/debin_models.tar.gz). If you want to try them, please put `crf` and `variable` folders in this directory:
```
$ wget https://files.sri.inf.ethz.ch/debin_models.tar.gz
$ tar -zxvf debin_models.tar.gz
$ rm debin_models.tar.gz
```