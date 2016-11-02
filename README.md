# DNS Proxy

[![Travis Build](https://travis-ci.org/Wattpad/kube-sqs-autoscaler.svg?branch=latest)](https://travis-ci.org/Wattpad/dns-server)
[![Coverage Status](https://coveralls.io/repos/github/Wattpad/dns-server/badge.svg?branch=master)](https://coveralls.io/github/Wattpad/dns-server?branch=master)

## Setup
* Python 2.7
* OpenSSL 0.9.8zh 14 Jan 2016 + (the docker container uses its own version in the container)

Run `create_certificate.sh` for https connections, and the resulting `.crt` file can be installed on client machines.
Run `mkdir databases` to store the sqlite3 db file.

## If using Docker (might work with lower versions):
* docker-compose version 1.8.0, build f3628c7
* Docker version 1.12.0, build 8eab29e

## Using docker-compose:
* `docker-compose up --build -d`

OR
* `docker-compose up --build -d "service_name"`

## Using docker run:
* Use the provided python scripts to run (`run_web.py`, `run_proxy.py`, `run_dns.py`) each service
