#!/usr/bin/env python3
#
# Copyright (c) 2018, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Expected input file format is a CSV file with:
#
# <FRAME_NUMBER, FRAME_ARRIVAL_TIME, FRAME_PAYLOAD_BYTES>
# E.g.:
# 1,1521534608.000000456,00:38:89:bd:a1:93:1d:15:(...)
# 2,1521534608.001000480,00:38:89:bd:a1:93:1d:15:(...)
#
# Frame number:         sequence number for each frame
# Frame arrival time:   Rx HW timestamp for each frame
# Frame Payload:        payload starting with 64bit timestamp (txtime)
#
# This can be easily generated with tshark with the following command line:
#  $ tshark -r CAPTURE.pcap -t e -E separator=, -T fields -e frame.number \
#           -e frame.time_epoch \
#           -e data.data > DATA.out
#
import argparse
import csv
import struct
import math
import sys

# TAI to UTC offset. Currently that is 37 seconds.
TAI_OFFSET = 37000000000


def compute_offsets_stats(file_path):
    with open(file_path) as f:
        count = mean = total_sqr_dist = 0.0
        min_t = sys.maxsize
        max_t = -sys.maxsize

        for line in csv.reader(f):
            arrival_tstamp = int(line[1].replace('.', ''))
            data = line[2].split(':')
            txtime = ''.join(data[0:8])
            txtime = bytearray.fromhex(txtime)
            txtime = struct.unpack('<Q', txtime)

            val = float(arrival_tstamp - txtime[0])
            val = (val - TAI_OFFSET) if val > TAI_OFFSET else val

            # Update statistics.
            # Compute the mean and variance online using Welford's algorithm.
            count += 1
            min_t = val if val < min_t else min_t
            max_t = val if val > max_t else max_t

            delta = val - mean
            mean = mean + (delta / count)
            new_delta = val - mean
            total_sqr_dist += delta * new_delta

        if count != 0.0:
            variance = total_sqr_dist / (count - 1)
            std_dev = math.sqrt(variance)

            print("min:\t\t%e" % min_t)
            print("max:\t\t%e" % max_t)
            print("jitter (pk-pk):\t%e" % (max_t - min_t))
            print("avg:\t\t%e" % mean)
            print("std dev:\t%e" % std_dev)
            print("count:\t\t%d" % count)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-f', dest='file_path', default=None, type=str,
        help='Path to input file (e.g. DATA.out) generated by tshark with:\
                tshark -r CAPTURE.pcap -t e -E separator=, -T\
                fields -e frame.number -e frame.time_epoch\
                -e data.data > DATA.out')

    args = parser.parse_args()

    if args.file_path is not None:
        compute_offsets_stats(args.file_path)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
