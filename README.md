# 1. [Docker container verification](./docker_verify.py)
This script will help you check the docker image (by calculating the manifest hash and layers) against the hash listed on the site (docker hub, quay, etc.).
Example usage:
```bash
python docker_verify.py bitnami/postgresql:15.2.0 bitnami.tar
```

# 2. [Npm file verification](./npm_verify.py)
This script will help you check the npm tarball file(s) (by calculating the tarball file hash) against the hash listed on the registry.npmjs.org.
Example usage:
```bash
python npm_verify.py -f chalk-5.2.0.tgz
```

# 3. [IP checker](./ip_checker.py)
A script for determining whether an IP address belongs to a country (based on abusepdb api)
```bash
python ip_checker.py -f ips.txt
```
