This is pretty much a heavy WIP.

This should aggregate Diameter AVPs/command codes/application IDs from different sources and put all this in a common sourced and historized backend, which should be fetchable from an unique web frontend then, and possibly exportable in other formats such as ABNF or Lua, etc.

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

In order to regenerate the SQLite database, please run (note: you need a public key with the ability to connect through SSH to `p1sec@protorisk.p1sec.com` in order to be able to mount HTML specifications from Protorisk, and to query the Protorisk MySQL database through the `sshtunel` Python module):

```
sudo apt install fuse python3 python3.7 sshfs
sudo python3.7 -m pip install --upgrade sqlalchemy sshtunnel
./regenerate.sh
```

## Other documentation

In order to read a comparison about the different data sources involved: https://docs.google.com/spreadsheets/d/1bW-yr-g6fjTXVy82h0mTMu4blYhEybYBg6OjJrW6N2g/edit#gid=0


