#!/usr/bin/env python
import struct
import hashlib
import bz2
import sys
import argparse
import io
import os
from enlighten import get_manager
import lzma
import update_metadata_pb2 as um

flatten = lambda l: [item for sublist in l for item in sublist]


def u32(x):
    return struct.unpack(">I", x)[0]


def u64(x):
    return struct.unpack(">Q", x)[0]


def verify_contiguous(exts):
    blocks = 0
    for ext in exts:
        if ext.start_block != blocks:
            return False

        blocks += ext.num_blocks

    return True


class Dumper:
    def __init__(self, payloadfile, out, images="", list=False):
        self.payloadfile = payloadfile
        self.out = out
        self.images = images
        self.list = list
        self.validate_magic()
        self.manager = get_manager()

    def run(self):
        if self.list:
            for part in self.dam.partitions:
                print("name: {}\tsha256: {}".format(part.partition_name.ljust(16), part.new_partition_info.hash.hex()))
        elif self.images == "":
            progress = self.manager.counter(
                total=len(self.dam.partitions),
                desc="Partitions",
                unit="part",
                position=1,
                color="green",
            )
            for part in self.dam.partitions:
                self.dump_part(part)
                progress.update()
        else:
            progress = self.manager.counter(
                total=len(self.images),
                desc="Partitions",
                unit="part",
                position=1,
                color="green",
            )
            for image in self.images:
                partition = [
                    part for part in self.dam.partitions if part.partition_name == image
                ]
                if partition:
                    self.dump_part(partition[0])
                else:
                    print("Partition %s not found in payload!" % image)
                progress.update()

        self.manager.stop()

    def validate_magic(self):
        magic = self.payloadfile.read(4)
        assert magic == b"CrAU"

        file_format_version = u64(self.payloadfile.read(8))
        assert file_format_version == 2

        manifest_size = u64(self.payloadfile.read(8))

        metadata_signature_size = 0

        if file_format_version > 1:
            metadata_signature_size = u32(self.payloadfile.read(4))

        manifest = self.payloadfile.read(manifest_size)
        self.metadata_signature = self.payloadfile.read(metadata_signature_size)
        self.data_offset = self.payloadfile.tell()

        self.dam = um.DeltaArchiveManifest()
        self.dam.ParseFromString(manifest)
        self.block_size = self.dam.block_size

    def data_for_op(self, op, out_file):
        self.payloadfile.seek(self.data_offset + op.data_offset)
        data = self.payloadfile.read(op.data_length)

        # assert hashlib.sha256(data).digest() == op.data_sha256_hash, 'operation data hash mismatch'

        if op.type == op.REPLACE_XZ:
            dec = lzma.LZMADecompressor()
            data = dec.decompress(data)
            out_file.seek(op.dst_extents[0].start_block * self.block_size)
            out_file.write(data)
        elif op.type == op.REPLACE_BZ:
            dec = bz2.BZ2Decompressor()
            data = dec.decompress(data)
            out_file.seek(op.dst_extents[0].start_block * self.block_size)
            out_file.write(data)
        elif op.type == op.REPLACE:
            out_file.seek(op.dst_extents[0].start_block * self.block_size)
            out_file.write(data)
        elif op.type == op.ZERO:
            for ext in op.dst_extents:
                out_file.seek(ext.start_block * self.block_size)
                out_file.write(b"\x00" * ext.num_blocks * self.block_size)
        else:
            print("Unsupported type = %d" % op.type)
            sys.exit(-1)

        return data

    def dump_part(self, part):
        print("Processing %s" % part.partition_name)

        out_file = open("%s/%s.img" % (self.out, part.partition_name), "wb")
        h = hashlib.sha256()

        operation_progress = self.manager.counter(
            total=len(part.operations), desc="Operations", unit="op", color="grey", leave=False
        )
        for op in part.operations:
            data = self.data_for_op(op, out_file)
            operation_progress.update()
        operation_progress.close()


def main():
    parser = argparse.ArgumentParser(description="Full OTA payload dumper")
    parser.add_argument(
        "payloadfile", type=argparse.FileType("rb"), help="payload file"
    )
    parser.add_argument(
        "-l", "--list", action='store_true', help="print partitions and exit"
    )
    parser.add_argument(
        "-p", "--partitions", nargs='*', default="", help="list of partitions to extract (example: boot vbmeta)"
    )
    parser.add_argument(
        "--out", default="output", help="output directory (default: 'output')"
    )
    args = parser.parse_args()

    # Check for --out directory exists
    if not os.path.exists(args.out):
        os.makedirs(args.out)

    dumper = Dumper(args.payloadfile, args.out, images=args.partitions, list=args.list)
    dumper.run()


if __name__ == "__main__":
    main()