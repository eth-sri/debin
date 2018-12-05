import os
import argparse
import subprocess


def get_args():
    parser = argparse.ArgumentParser('Debin to hack binaries. '\
        'This script is used to train CRF model with Nice2Predict. Make sure you have enough disk space.')

    parser.add_argument('--bin_list', dest='bin_list', type=str, required=True,
                        help='list of binaries to train.')
    parser.add_argument('--bin_dir', dest='bin_dir', type=str, required=True,
                        help='directory of the stripped binaries.')
    parser.add_argument('--debug_dir', dest='debug_dir', type=str, required=True,
                        help='directory of debug information files.')
    parser.add_argument('--bap_dir', dest='bap_dir', type=str, default='',
                        help='directory of cached BAP-IR files.')
    parser.add_argument('--workers', dest='workers', type=int, default=1,
                        help='number of workers (i.e., parallization).')
    parser.add_argument('--out_model', dest='out_model', type=str, required=True,
                        help='prefix of the output model.')
    parser.add_argument('--bin_to_graph', dest='bin_to_graph', type=str, default='py/bin_to_graph.py',
                        help='path to bin_to_graph.py script')
    parser.add_argument('--n2p_train', dest='n2p_train', type=str, required=True,
                        help='Nice2Predict train executable.')
    parser.add_argument('--max_labels_z', dest='max_labels_z', type=int, default=8,
                        help='max_labels_z parameter of Nice2Predict')
    parser.add_argument('--log_dir', dest='log_dir', type=str, required=True,
                        help='log directory')
    parser.add_argument('--valid_labels', dest='valid_labels', type=str, required=True,
                        help='valid_label file of Nice2Predict.')

    args = parser.parse_args()
    return args


def main():
    args = get_args()

    if not os.path.exists(args.log_dir):
        os.makedirs(args.log_dir)

    if args.bap_dir == '':
        cmd = 'cat {} | xargs -I % -P{} python3 {} --binary {} --debug_info {} --graph {}'.format(
            args.bin_list,
            args.workers,
            args.bin_to_graph,
            os.path.join(args.bin_dir, '%'),
            os.path.join(args.debug_dir, '%'),
            os.path.join(args.log_dir, '%')
        )
    else:
        cmd = 'cat {} | xargs -I % -P{} python3 {} --binary {} --debug_info {} --bap {} --graph {}'.format(
            args.bin_list,
            args.workers,
            args.bin_to_graph,
            os.path.join(args.bin_dir, '%'),
            os.path.join(args.debug_dir, '%'),
            os.path.join(args.bap_dir, '%'),
            os.path.join(args.log_dir, '%')
        )
    subprocess.call(cmd, shell=True)

    cmd = 'cat {} | xargs -I % sh -c \'cat {}\' > {}'.format(
        args.bin_list,
        os.path.join(args.log_dir, '%'),
        os.path.join(args.log_dir, 'feature.json')
    )
    subprocess.call(cmd, shell=True)

    cmd = '{} --input {} --log_dir {} --valid_labels {} --out_model {} --num_threads {} --training_method pl --max_labels_z {}'.format(
        args.n2p_train,
        os.path.join(args.log_dir, 'feature.json'),
        args.log_dir,
        args.valid_labels,
        args.out_model,
        args.workers,
        args.max_labels_z
    )
    subprocess.call(cmd, shell=True)


if __name__ == '__main__':
    main()