#!/usr/bin/env python
"""
Expand testcase into individual files
"""
import os
import sys
import struct
import testdata
import argparse

ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
if os.path.exists(os.path.join(ROOT_DIR, "ebpf")):
    # Running from source tree
    sys.path.insert(0, ROOT_DIR)

import ebpf.assembler
import ebpf.disassembler

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('name')
    parser.add_argument('path')
    args = parser.parse_args()

    data = testdata.read(args.name + '.data')
    assert data

    if not os.path.isdir(args.path):
        os.makedirs(args.path)

    def writefile(name, contents):
        file("%s/%s" % (args.path, name), "w").write(contents)

    if 'mem' in data:
        writefile('mem', data['mem'])

        # Probably a packet, so write out a pcap file
        writefile('pcap',
            struct.pack('=IHHIIIIIIII',
                0xa1b2c3d4, # magic
                2, 4, # version
                0, # time zone offset
                0, # time stamp accuracy
                65535, # snapshot length
                1, # link layer type
                0, 0, # timestamp
                len(data['mem']), # length
                len(data['mem'])) # length
            + data['mem'])

    if 'raw' in data:
        code = ''.join(struct.pack("=Q", x) for x in data['raw'])
    elif 'asm' in data:
        code = ebpf.assembler.assemble(data['asm'])
    else:
        code = None

    if code:
        writefile('code', code)

    if 'asm' in data:
        writefile('asm', data['asm'])
    elif code:
        writefile('asm', ebpf.disassembler.disassemble(code))


if __name__ == "__main__":
    main()
