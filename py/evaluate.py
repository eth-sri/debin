import os
import sys
import argparse
import pickle
import subprocess
from common.config import Config
from common.timer import TIMER
from binary import Binary


def get_args():
    parser = argparse.ArgumentParser(description='Debin to hack binaries. ' \
        'This script turns a binary and its debug information into a conditional dependency graph with ground truth. ' \
        'This is needed by Nice2Predict to train a CRF model.')

    parser.add_argument('--binary', dest='binary', type=str, default='', required=True,
                        help='Path of the binary you want to analyze.')
    parser.add_argument('--debug_info', dest='debug_info', type=str, default='', required=True,
                        help='Path of the debugging info.')
    parser.add_argument('--bap', dest='bap', type=str, default='',
                        help='path of cached BAP-IR file.')

    parser.add_argument('-two_pass', dest='two_pass', action='store_true', default=False,
                        help='whether to use two passes (variable classification and structured prediction). Setting it to false only will only invoke structured prediction.')
    parser.add_argument('--fp_model', dest='fp_model', type=str, default='',
                        help='Path of the models for the first pass (variable classification).')

    parser.add_argument('--n2p_url', dest='n2p_url', type=str, default='', required=True,
                        help='URL of n2p server.')
    parser.add_argument('--stat', dest='stat', type=str, required=True,
                        help='Path of output statistics file.')

    args = parser.parse_args()
    return args


def main():
    args = get_args()

    config = Config()

    config.MODE = config.TRAIN

    config.BINARY_PATH = args.binary
    config.BINARY_NAME = args.binary
    config.BAP_FILE_PATH = args.bap
    config.DEBUG_INFO_PATH = args.debug_info

    config.N2P_SERVER_URL = args.n2p_url
    config.STAT_PATH = args.stat

    config.TWO_PASS = args.two_pass
    config.FP_MODEL_PATH = args.fp_model
    if config.TWO_PASS:
        reg_dict = open(os.path.join(config.FP_MODEL_PATH, 'reg.dict'), 'rb')
        reg_model = open(os.path.join(config.FP_MODEL_PATH, 'reg.model'), 'rb')
        reg_support = open(os.path.join(config.FP_MODEL_PATH, 'reg.support'), 'rb')
        config.REG_DICT = pickle.load(reg_dict, encoding='latin1')
        config.REG_SUPPORT = pickle.load(reg_support, encoding='latin1')
        config.REG_DICT.restrict(config.REG_SUPPORT.get_support())
        config.REG_MODEL = pickle.load(reg_model, encoding='latin1')
        config.REG_MODEL.n_jobs = 1

        off_dict = open(os.path.join(config.FP_MODEL_PATH, 'off.dict'), 'rb')
        off_model = open(os.path.join(config.FP_MODEL_PATH, 'off.model'), 'rb')
        off_support = open(os.path.join(config.FP_MODEL_PATH, 'off.support'), 'rb')
        config.OFF_DICT = pickle.load(off_dict, encoding='latin1')
        config.OFF_SUPPORT = pickle.load(off_support, encoding='latin1')
        config.OFF_DICT.restrict(config.OFF_SUPPORT.get_support())
        config.OFF_MODEL = pickle.load(off_model, encoding='latin1')
        config.OFF_MODEL.n_jobs = 1

    with open(config.BINARY_PATH, 'rb') as elffile, open(config.DEBUG_INFO_PATH, 'rb') as debug_elffile:
        TIMER.start_scope('0ALL')
        b = Binary(config, elffile, debug_elffile)
        TIMER.start_scope('2CRF')
        b.set_test_result_from_server(True)
        TIMER.end_scope()
        TIMER.end_scope()
        b.dump_stat()

    if config.TWO_PASS:
        reg_dict.close()
        reg_support.close()
        reg_model.close()
        off_dict.close()
        off_support.close()
        off_model.close()


if __name__ == '__main__':
    main()