import os
import json
import ecdsa
import base64
import tarfile
import hashlib
import colorama
import argparse
import requests
from typing import Tuple


keys_url = "https://registry.npmjs.org/-/npm/v1/keys"


def get_npm_keys(keys_url: str):
    keys_json = requests.get(keys_url).json()
    for key in keys_json["keys"]:
        keyid = key["keyid"]
        yield keyid, key


def pack_dist(url: str) -> dict:
    dist = requests.get(url).json()
    return dist["dist"] if "dist" in dist else (url, requests.get(url).text)


def get_sha256_package_digest(
    package_name: str, package_version: str, integrity: str
) -> bytes:
    # ${package.name}@${package.version}:${package.dist.integrity}
    return hashlib.sha256(
        f"{package_name}@{package_version}:{integrity}".encode("utf-8")
    ).digest()


def get_file_sha512(filename: str) -> bytes:
    md = hashlib.sha512()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md.update(chunk)
    return md.digest()


def get_pack_name_and_ver(packet: str) -> Tuple[str, str]:
    p = "package/package.json"
    with tarfile.open(packet) as f:
        pack_json_name = (
            p
            if p in f.getnames()
            else [e for e in f.getnames() if p.split("/")[1] in e][0]
        )
        package_json = json.loads(f.extractfile(pack_json_name).read().decode("utf-8"))
        pack_name = package_json["name"]
        pack_ver = package_json["version"]

        return pack_name, pack_ver


def compare_hashes(file: str, calculated_hash: str, hash_from_registry: str) -> str:
    if calculated_hash != hash_from_registry:
        return (
            f"\n{colorama.Fore.RED}Wrong hash!{colorama.Style.RESET_ALL}\n"
            f"{'Got': <8} {calculated_hash}\n"
            f"Expected {hash_from_registry}\n"
        )
    else:
        return (
            f"\n{colorama.Fore.GREEN}OK.{colorama.Style.RESET_ALL}\n"
            f"Hash of {os.path.basename(file)} checked!\n"
            f"{os.path.basename(file)}: {calculated_hash}\n"
        )


def check_sig(file: str, dist: str, digest: str) -> str:
    keys = dict(get_npm_keys(keys_url))

    for sig in dist["signatures"]:
        if sig["keyid"] in keys:
            key_str = f"-----BEGIN PUBLIC KEY-----\n{keys[sig['keyid']]['key']}\n-----END PUBLIC KEY-----"
            key = ecdsa.VerifyingKey.from_pem(key_str, hashfunc=hashlib.sha256)
            try:
                key.verify_digest(
                    base64.b64decode(sig["sig"]),
                    digest,
                    sigdecode=ecdsa.util.sigdecode_der,
                )
            except ecdsa.BadSignatureError:
                return f"{colorama.Fore.RED}Wrong signature of {os.path.basename(file)}!{colorama.Style.RESET_ALL}"
            else:
                return (
                    f"{colorama.Fore.GREEN}Signature of {os.path.basename(file)} checked!{colorama.Style.RESET_ALL}\n"
                    f"package dist (json):\n{json.dumps(dist, indent=4)}\n"
                    f"used key (json):\n{json.dumps(keys[sig['keyid']], indent=4)}"
                )


def main(file: str):
    pack_name, pack_ver = get_pack_name_and_ver(file)

    snyk_pack_name = pack_name.replace("/", "%2F") if "/" in pack_name else pack_name

    url = f"https://registry.npmjs.org/{pack_name}/{pack_ver}"
    dist = pack_dist(url)
    file_hash = get_file_sha512(file)
    file_hash_str = f"sha512-{base64.b64encode(file_hash).decode('utf-8')}"

    if isinstance(dist, dict):
        print(
            f"https://snyk.io/advisor/npm-package/{snyk_pack_name}/{pack_ver}\n"
            + url
            + compare_hashes(file, file_hash_str, dist["integrity"])
            + "-" * 50
        )

        digest = get_sha256_package_digest(pack_name, pack_ver, dist["integrity"])

        print(check_sig(file, dist, digest) + "\n" + "#" * 50)
    else:
        print(os.path.basename(file), dist + "#" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        usage="%(prog)s [options]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-f", "--file", help=".tgz file to verify")
    parser.add_argument("-p", "--path", help="directory with .tgz files")
    args = parser.parse_args()

    if args.file:
        if args.file.endswith(".tgz"):
            main(args.file)
        else:
            print("ERROR. No .tgz files found.")

    elif args.path:
        files = [
            f
            for f in os.listdir(args.path)
            if os.path.isfile(os.path.join(args.path, f)) and f.endswith(".tgz")
        ]
        if len(files) == 0:
            print("ERROR. No .tgz files found.")
        for file in files:
            main(os.path.join(args.path, file))

    else:
        print(parser.print_help())
