# Keyserver

created for personal use

uses key from ~/.base0/master.key
to derive more keys without giving the archive or archive keys to user to reduce mistakes.

keyserver sits as daemon and saves password once entered for 5 minutes.

to use,
install with ./install.sh

give it pass, mfd unlock
use on python see python code(test.py)


# Keyserver

Created for personal use.

## Overview
Uses the master key from `~/.base0/master.key` to derive sub-keys. This architecture reduces mistakes by preventing direct user access to the master archive or archive keys.

* **Behavior**: Sits as a daemon and derives password from master key for 5min after giving it password.

## Installation
```bash
# install it to user
./install.sh

# for setting intital master.key(do at some point)
mfs keygen
```

To provide the password
```bash
mfs unlock
```

## Python Integration
Just copy mfs.py to desired codebase.
See test.py for usage.

## Maintenance
Uninstall: `./uninstall.sh`

Logs: `journalctl --user -u keyserver.service -f`

* Used llm during its creation. So, skip if ...
