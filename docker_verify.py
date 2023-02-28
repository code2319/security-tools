#!/usr/bin/env python3
import os
import json
import logging
import getpass
import hashlib
import tarfile
import platform
import argparse
import colorama
import requests
import requests.auth
from typing import Tuple
import urllib.parse as urlparse


from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DOCKER_REGISTRY_HOST = "registry-1.docker.io"


def image_name_parser(image: str) -> tuple:
    registry = ""
    tag = "latest"

    idx = image.find("/")
    if idx > -1 and ("." in image[:idx] or ":" in image[:idx]):
        registry = image[:idx]
        image = image[idx + 1 :]

    idx = image.find("@")
    if idx > -1:
        tag = image[idx + 1 :]
        image = image[:idx]

    idx = image.find(":")
    if idx > -1:
        tag = image[idx + 1 :]
        image = image[:idx]

    idx = image.find("/")
    if idx == -1 and registry == "":
        image = "library/" + image

    return registry or DOCKER_REGISTRY_HOST, image, tag


def www_auth(hdr: str) -> Tuple[str, dict]:
    auth_scheme, info = hdr.split(" ", 1)

    out = {}
    for part in info.split(","):
        k, v = part.split("=", 1)
        out[k] = v.replace('"', "").strip()

    return auth_scheme, out


def sha256tar(file, chunk_size=131072) -> str:
    h = hashlib.sha256()
    while 1:
        chunk = memoryview(file.read(chunk_size))
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


class ImageVerifier:
    def __init__(
        self,
        user: str = None,
        password: str = None,
        ssl: bool = True,
        verbose: bool = True,
        save_cache: bool = False,
    ):
        self._ssl = ssl
        self._user = user
        self._password = password
        self._session = requests.Session()
        self._session.verify = False
        self._save_cache = save_cache

        if verbose:
            logging.basicConfig(level=logging.DEBUG, filemode="a", filename="log.log")

    def _make_url(self, registry: str, ns: str) -> str:
        return urlparse.urlunsplit(
            ("https" if self._ssl else "http", registry, f"/v2/{ns}/", None, None)
        )

    def _auth(self, resp: requests.Response):
        self._session.headers.pop("Authorization", "")

        auth = (
            requests.auth.HTTPBasicAuth(self._user, self._password)
            if self._user
            else None
        )

        if not resp.headers["www-authenticate"]:
            raise ValueError("empty the www-authenticate header")

        auth_scheme, parsed = www_auth(resp.headers["www-authenticate"])
        url_parts = list(urlparse.urlparse(parsed["realm"]))
        query = urlparse.parse_qs(url_parts[4])
        query.update(service=parsed["service"])

        if "scope" in parsed:
            query.update(scope=parsed["scope"])

        url_parts[4] = urlparse.urlencode(query, True)

        r = self._session.get(urlparse.urlunparse(url_parts), auth=auth)
        r.raise_for_status()

        self._session.headers.update(Authorization=f"{auth_scheme} {r.json()['token']}")

    def _req(
        self, url, method="GET", headers: dict = None, stream: bool = None, **kwargs
    ) -> Tuple[str, requests.models.Response]:
        r = self._session.request(method, url, headers=headers, stream=stream, **kwargs)
        if r.status_code == requests.codes.unauthorized:
            self._auth(r)
            r = self._session.request(
                method, url, headers=headers, stream=stream, **kwargs
            )

        logging.debug(f"Response headers: {r.headers}")
        logging.debug(f"Response: {r.content}")
        if r.status_code != requests.codes.ok:
            logging.error(f"Response: {r.content}")
            r.raise_for_status()

        # print(f"{colorama.Fore.RED}{type(r)}{colorama.Style.RESET_ALL}")
        return url, r

    def _manifests_req(
        self, url: str, tag: str, media_type: str
    ) -> Tuple[str, requests.models.Response]:
        url, m = self._req(
            urlparse.urljoin(url, f"manifests/{tag}"), headers={"Accept": media_type}
        )
        return url, m

    def get_manifest_list(
        self, url: str, tag: str
    ) -> Tuple[str, requests.models.Response]:
        url, m = self._manifests_req(
            url, tag, "application/vnd.docker.distribution.manifest.list.v2+json"
        )
        return url, m

    def verify(self, image: str, image_platform: str, image_file: str):
        if image_platform:
            image_os, image_arch = image_platform.split("/")
        else:
            image_os, image_arch = "linux", platform.machine()

        reg, ns, tag = image_name_parser(image)
        url = self._make_url(reg, ns)

        print(f"{tag}: Verifing from {ns}")

        manifests_url, manifests_list = self.get_manifest_list(url, tag)
        manifests_list_data = manifests_list.json()
        logging.debug(f"Manifest list headers: {manifests_list.headers}")

        tag_digest = None
        media_type = "application/vnd.docker.distribution.manifest.v2+json"
        for manifest in manifests_list_data.get("manifests", []):
            if (
                manifest["platform"]["architecture"] == image_arch
                and manifest["platform"]["os"] == image_os
            ):
                tag_digest = manifest["digest"]
                media_type = manifest["mediaType"]
                break

        if not (tag_digest or tag):
            raise Exception(
                f"Selected architecture or os ({image_platform}) not supported by package"
            )

        manifest_url, image_manifest_res = self._manifests_req(
            url, tag_digest or tag, media_type
        )
        
        image_manifest_digest = (
            f"sha256:{hashlib.sha256(image_manifest_res.content).hexdigest()}"
        )
        
        print(
            colorama.Fore.RED
            + "Compare this hash: "
            + colorama.Style.RESET_ALL
            + colorama.Fore.CYAN
            + image_manifest_digest
            + colorama.Style.RESET_ALL
            + "\n"
        )
        
        if tag_digest and image_manifest_digest != tag_digest:
            raise Exception(
                f"{colorama.Fore.RED}Wrong image manifest digest. "
                f"Got {image_manifest_digest}, expected {tag_digest}{colorama.Style.RESET_ALL}"
            )

        image_manifest = image_manifest_res.json()

        if "config" in image_manifest.keys():
            if "digest" in image_manifest["config"].keys():
                image_id = image_manifest["config"]["digest"]
            else:
                raise Exception(f"Cant verify image config in tar. No digest data")
        else:
            raise Exception(f"Cant verify image config in tar. No config section")

        
        with tarfile.open(image_file, "r") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".json") and member.name != "manifest.json":
                    if member.name is not None:
                        json_inside_image = member.name
            tar_manifest = json.load(tar.extractfile("manifest.json"))
            tar_image_config = tar.extractfile(tar_manifest[0]["Config"])
            if not tar_image_config:
                raise Exception(f"No image config found!")

            image_config = tar_image_config.read()
            tar_image_config_digest = (
                f"sha256:{hashlib.sha256(image_config).hexdigest()}"
            )
            print(
                f"The hash of the config file {json_inside_image} is {tar_image_config_digest}\n"
            )
            if tar_image_config_digest != image_id:
                raise Exception(
                    f"Wrong image config in tar. Got {tar_image_config_digest}, expected {image_id}"
                )

            image_config = json.loads(image_config)
            diff_ids = image_config["rootfs"]["diff_ids"]
            have_wrong_layer = False
            for i, tar_manifest_layer_filename in enumerate(tar_manifest[0]["Layers"]):
                layer_digest = (
                    f"sha256:{sha256tar(tar.extractfile(tar_manifest_layer_filename))}"
                )

                if layer_digest != diff_ids[i]:
                    have_wrong_layer = True
                    print(
                        colorama.Fore.RED
                        + "NOT OK. "
                        + colorama.Style.RESET_ALL
                        + f"Wrong layer digest for {tar_manifest_layer_filename}\n"
                        + f"Got: {layer_digest}\n"
                        + f"Expected: {diff_ids[i]}"
                    )
                else:
                    print(
                        colorama.Fore.GREEN
                        + "OK. "
                        + colorama.Style.RESET_ALL
                        + f"The hash of the layer '{tar_manifest_layer_filename}' "
                        + f"matches the data in the config file ({json_inside_image}) "
                        + f"and is equal to '{diff_ids[i]}'"
                    )

            if have_wrong_layer:
                raise Exception(f"Image have some wrong layers")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="docker_verify.py",
        usage=f"\n{colorama.Fore.CYAN}docker_verify.py bitnami/postgresql:14.5.0 postgresql.tar\n"
        f"docker_verify.py quay.io/git-chglog/git-chglog@sha256:322eb9ab6db299b5478c02024265f7aec7e736dd82b996c52c420acb116ce50e git-chglog.tar{colorama.Style.RESET_ALL}",
    )

    parser.add_argument("image", nargs=1)
    parser.add_argument("image_file", nargs=1)
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument("--user", "-u", type=str, help="Registry login")
    parser.add_argument(
        "--platform",
        type=str,
        default="linux/amd64",
        help="Set platform if server is multi-platform capable",
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--password", "-p", type=str, help="Registry password")
    grp.add_argument("-P", action="store_true", help="Registry password (interactive)")
    arg = vars(parser.parse_args())

    if arg.pop("P"):
        arg["password"] = getpass.getpass()

    image = arg.pop("image")[0]
    image_file = arg.pop("image_file")[0]
    image_platform = arg.pop("platform")

    v = ImageVerifier(**arg)
    v.verify(image, image_platform, image_file)
