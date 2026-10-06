# diameter-db

The purpose of this application is to aggregate Diameter AVPs/command codes/application IDs from different sources, and to put all this in a common sourced and historized backend, which should then be fetchable from an unique web frontend, and possibly exportable into other formats such as SQLite or CSV (why not later Lua or ABNF), etc.

It currently aggregates data from five different sources: [Wireshark](https://github.com/wireshark/wireshark/tree/master/resources/protocols/diameter), [Diafuzzer](https://github.com/Orange-OpenSource/diafuzzer), IETF specifications, 3GPP specifications and [IANA](https://www.iana.org/assignments/aaa-parameters/aaa-parameters.xhtml).

For examples of how to use with database with your code, you can refer to the [`examples/`](https://github.com/P1sec/diameter-db/tree/master/examples) directory.

All this data is currently visualizable and exportable through a web frontend accessible [here](https://diameter-db.p1sec.fr/).

## Clone the source code

In order to clone it including the `compare_data_sources/{wireshark,diafuzzer}` directories, use:

```bash
sudo apt install git
git clone --recursive git@github.com:P1sec/diameter-db.git
cd diameter-db/
```

(Or, if you have already cloned the repo forgetting to include `--recursive`):

```bash
git submodule update --init --recursive
```

Update the nested repositories from their respective remotes:

```bash
git submodule update --recursive --remote --merge
```


## Data generation procedure

The following command will run the data generation procedure for both the web application and the data regeneration routine:

```bash
sudo apt install fuse python3-pip python3-dev p7zip-full sshfs sqlite3
sudo snap install --classic astral-uv
uv tool install -e .
```

In order to regenerate the SQLite database, and to indexate its contents in Elasticsearch if installed, please run (note: you need a public key with the ability to connect through SSH to `p1sec@protorisk` in order to be able to mount HTML specifications from Protorisk, and to query the Protorisk MySQL database through the `sshtunnel` Python module):

```bash
$ cat ~/.ssh/.config
(...)
Host protorisk
    Hostname protorisk
    User p1sec
    ProxyCommand "/usr/local/bin/tsh" proxy ssh --user=$PROXY_USER --proxy=tele.$PROXY_DOMAIN %r@%h:%p
```

```bash
sudo sed -ri 's/#user_allow_other/user_allow_other/' /etc/fuse.conf
tsh login
```

```bash
diameter-db-regenerate
```

## How to run the application locally

You will find the commands which allow to install the dependencies for the web application above.

Before running your application, you should known that is shares its authentication mechanisms with the Protorisk SSO. As such, it should be put under a `.p1sec.fr` or `.p1sec.com` domain (if needed through your hosts file).

You should also adapt the Flask session cookie salt, in order to provide correct interoperability with the Protorisk SSO:

```bash
cd src/diameter_db/webapp/
cp flask_salt.sample.py flask_salt.py 
nano flask_salt.py
```

And create a vhost under `*.p1sec.fr` for cross-domain authentication:

```bash
echo 127.0.0.1 diameter-db-local.p1sec.fr | sudo tee -a /etc/hosts
```

To run the application locally, please run:

```bash
diameter-db-webapp
xdg-open http://diameter-db-local.p1sec.fr:9999
```

## Install the application on a shared Nginx server

You should run the following commands:


Setup Hypercorn and nginx:

```bash
uv tool install uv
uv tool install hypercorn
sudo cp ~/diameter-db/src/diameter_db/webapp/diameter-db.service /etc/systemd/system/diameter-db.service
sudo systemctl daemon-reload
sudo systemctl enable diameter-db
sudo systemctl start diameter-db

sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

sudo cp ~/diameter-db/src/diameter_db/webapp/nginx-site-diameter-db.conf /etc/nginx/sites-enabled/diameter-db.conf
sudo systemctl restart nginx
```

Setup the letsencrypt certificate and the local Elasticsearch server: see the commands in the [Protorisk README](https://project.p1sec.com/projects/html-3gpp-documentation/repository/revisions/master/entry/README.md)

## Other documentation

In order to read a comparison about the different data sources involved: https://docs.google.com/spreadsheets/d/1bW-yr-g6fjTXVy82h0mTMu4blYhEybYBg6OjJrW6N2g/edit#gid=0


