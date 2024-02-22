# xIM
Cross process / container / pod Isolation Monitor

---

Note: Use the `python-3.6.9` branch, if needed.

---
### Overview

Code execution can be isolated at various granularities, including that of (Linux) processes, containers, or (Kubernetes) pods. Isolation is intended to prevent interaction, thereby limiting the scope of analysis when reliability or security concerns arise. Flows that cross isolation boundaries are of particular interest for detecting anomalous activity.

xIM can be run in one of three modes: cross-process, cross-container, or cross-pod tracking:

```
> ./xim.py --help
usage: xim.py [-h] [-d] [-g GRANULARITY]

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Emit debug messages (if logging active)
  -g GRANULARITY, --granularity GRANULARITY
                        Isolation monitoring granularity (process / container / pod)
```

---

### Setup

xIM depends on Sysdig. This can be installed on Ubuntu with:

```
# Update software
sudo apt update && sudo apt upgrade -y
sudo apt install curl gnupg software-properties-common -y

# Install Sysdig
sudo curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash
```

xIM requires root privileges since it monitors system calls from all processes.

xIM and its dependencies can generate system calls as well. To avoid monitoring these, the user that xIM runs as is noted. Calls from processes of this user are excluded.

Consequently, it is advisable to create a `xim` user (and use it for running xIM):

```
# Setup xIM
adduser --disabled-password --gecos 'xApp Isolation Monitor' xim
echo 'xim ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/xim
mkdir /home/xim/bin
chown -R xim.xim /home/xim/bin/xim.py
```

(Above `xim.py` is assumed to be installed in `/home/xim/bin`.)

---

### Internals

xIM uses Sysdig to monitor I/O events -- that is, read(), write() etc. system calls -- of all processes on the host. Sysdig uses eBPF to only add instrumentation needed to track the required information. This makes the monitoring lightweight.

When a write occurs from a process / container / pod, the path at which it occurred is noted. When a read occurs, a check is done to see if any process / container / pod has written to the path previously. If so, the triple of the writer, path, and reader are reported (if they have not previously been output).
