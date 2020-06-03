#!/usr/bin/env python3

import os
import sys
import stat
import logging
import tarfile
import argparse
import tempfile
import urllib.request

log = logging.getLogger(__name__)

KUSTOMIZE_URL = "https://github.com/kubernetes-sigs/kustomize/releases/download/v3.2.0/kustomize_3.2.0_linux_amd64"
GO_URL = "https://dl.google.com/go/go1.14.1.linux-amd64.tar.gz"
KUBECTL_URL = "https://storage.googleapis.com/kubernetes-release/release/v1.18.2/bin/linux/amd64/kubectl"
K3D_URL = "https://github.com/rancher/k3d/releases/download/v3.0.1/k3d-linux-amd64"


def parse_args():
    parser = argparse.ArgumentParser(description="Install binary dependencies")
    parser.add_argument("output_dir", metavar="OUTPUT_DIR", type=str,
                        help="Where to place the binaries.")
    return parser.parse_args()


def download_to(url, output_path):
    with open(output_path, "wb") as f:
        res = urllib.request.urlopen(url)
        data = res.read()
        f.write(data)


def download_from_tar(url, output_dir, paths_inside_tar=[], flatten=True):
    if not isinstance(paths_inside_tar, list):
        paths_inside_tar = list(paths_inside_tar)
    with tempfile.NamedTemporaryFile() as tarball:
        download_to(url, tarball.name)
        tar = tarfile.open(tarball.name)

        members = [tar.getmember(p) for p in paths_inside_tar]
        if not paths_inside_tar:
            members = tar.getmembers()

        for m in members:
            if flatten:
                m.name = os.path.basename(m.name)
            tar.extract(m, output_dir)


def main():
    global log
    logging.basicConfig(level=logging.INFO)

    args = parse_args()

    log.info("Installing go...")
    download_from_tar(GO_URL, args.output_dir, flatten=False)

    log.info("Installing kustomize...")
    download_to(KUSTOMIZE_URL, os.path.join(args.output_dir, "kustomize"))
    os.chmod(os.path.join(args.output_dir, "kustomize"), stat.S_IRWXU)

    log.info("Installing kubectl...")
    download_to(KUBECTL_URL, os.path.join(args.output_dir, "kubectl"))
    os.chmod(os.path.join(args.output_dir, "kubectl"), stat.S_IRWXU)

    log.info("Installing k3d...")
    download_to(K3D_URL, os.path.join(args.output_dir, "k3d"))
    os.chmod(os.path.join(args.output_dir, "k3d"), stat.S_IRWXU)


if __name__ == "__main__":
    main(sys.exit(main()))
