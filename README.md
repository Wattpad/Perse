#Setup
* Python 2.7
* postgresql >= 9.4
* OpenSSL 0.9.8zh 14 Jan 2016

Run `create_certificate.sh` for https connections, and the resulting `.crt` file can be installed on client machines.
Run `mkdir data` for the database volume that the postgresql service will be using.

#If using Docker (might work with lower versions):
* docker-compose version 1.8.0, build f3628c7
* Docker version 1.12.0, build 8eab29e

#Using docker-compose:
* `docker-compose up --build -d`

OR
* `docker-compose up --build -d "service_name"`

#Using docker:
* Start the postgresql container (`docker run -v /PATH/TO/THIS/REPO/data:/var/lib/postgresql/data -p "5432:542" -e POSTGRES_DB=rewrite_db -e POSTGRES_USER=docker -e POSTGRES_PASSWORD=docker -d postgres:9.5.4`)
* Use the provided python scripts to run (`run_web.py`, `run_proxy.py`, `run_dns.py`) each service

