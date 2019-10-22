The purpose of this application is to aggregate Diameter AVPs/command codes/application IDs from different sources and puts all this in a common sourced and historized backend, which should be fetchable from an unique web frontend then, and possibly exportable in other formats such as SQLite or CSV (why not later Lua or ABNF), etc.

It currently aggregates data from five different sources: [Wireshark](https://github.com/wireshark/wireshark/tree/master/diameter), [Diafuzzer](https://github.com/Orange-OpenSource/diafuzzer), IETF specifications, 3GPP specifications and [IANA](https://www.iana.org/assignments/aaa-parameters/aaa-parameters.xhtml).

For examples of how to use with database with your code, you can refer to the [`examples/`](https://github.com/P1sec/diameter-db/tree/master/examples) directory.

All this data is currently visualizable and exportable through a web frontend accessible [here](https://diameter-db.p1sec.fr/).

## Clone the source code

In order to clone it including the `compare_data_sources/{wireshark,diafuzzer}` directories, use:

```
git clone --recursive https://github.com/P1sec/diameter-db
```

Update the nested repositories from their respective remotes:

```
git submodule update --recursive --remote --merge
```


## Data generation procedure

The following command will run the data generation procedure for both the web application and the data regeneration routine:

```
sudo apt install fuse python3-pip git python3.7 sshfs p7zip-full sqlite3
sudo python3.7 -m pip install --upgrade cython # Avoid conflicts with older cython versions installed on the system when installing aiohttp
sudo python3.7 -m pip install --upgrade sqlalchemy sshtunnel quart requests itsdangerous==0.24 aiohttp
```

In order to regenerate the SQLite database, and to indexate its contents in Elasticsearch if installed, please run (note: you need a public key with the ability to connect through SSH to `p1sec@protorisk.p1sec.com` in order to be able to mount HTML specifications from Protorisk, and to query the Protorisk MySQL database through the `sshtunnel` Python module):

```
./regenerate.sh
```

## How to run the application locally

You will find the command which is able to install the dependencies for the web application above.

In order to run the application, Python 3.7 (present in Ubuntu 18.04 LTS repositories, not as the default `python` (2.7) or `python3` (3.6) command but `python3.7`) is required.

itsdangerous==0.24 is also required, because itsdangerous 1.1.0 will not accept cookies signed by 0.24, while 0.24 will accepts cookies signed by 1.1.0, and Protorisk originally runs on 0.24; upgrading Protorisk to 1.0 would unnecessarily log off users; 1.1.0 is the version that comes just after 0.24, despite its name)

Before running your application, you should known that is shares its authentication mechanisms with the Protorisk SSO. As such, it should be put under a `.p1sec.fr` or `.p1sec.com` domain (if needed through your hosts file).

You should also adapt the Flask session cookie salt, in order to provide correct interoperability with the Protorisk SSO:

```
cp webapp/flask_salt.sample.py webapp/flask_salt.py 
nano webapp/flask_salt.py
```

To run the application locally, please run:

```
./webapp/app.py
```

## Install the application on the Protorisk server

You should run the following commands:


Setup Hypercorn and nginx:

```
sudo cp ~/diameter-db/webapp/diameter-db.service /etc/systemd/system/diameter-db.service
sudo systemctl daemon-reload
sudo systemctl enable diameter-db
sudo systemctl start diameter-db

sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

sudo cp ~/diameter-db/webapp/nginx-site-diameter-db.conf /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

Setup the letsencrypt certificate and the local Elasticsearch server: see the commands in the [Protorisk README](https://project.p1sec.com/projects/html-3gpp-documentation/repository/revisions/master/entry/README.md)

## Other documentation

In order to read a comparison about the different data sources involved: https://docs.google.com/spreadsheets/d/1bW-yr-g6fjTXVy82h0mTMu4blYhEybYBg6OjJrW6N2g/edit#gid=0


