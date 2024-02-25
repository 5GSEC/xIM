# xIM
Cross process / container / pod Isolation Monitor

---

Note: Use the `python-3.6.9` branch for the NDSS '24 [5G-Spector Artifact](https://github.com/5GSEC/5G-Spector/wiki/5G%E2%80%90Spector-Artifact-in-a-Simulated-LTE-Network).

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

### Output

Below is sample output from xIM, run at cross-process granularity. 

(This was collected on the [5G-Spector Artifact](https://github.com/5GSEC/5G-Spector/wiki/5G%E2%80%90Spector-Artifact-in-a-Simulated-LTE-Network), after following the steps upto and including the creation of [Normal UE connections](https://github.com/5GSEC/5G-Spector/wiki/5G%E2%80%90Spector-Artifact-in-a-Simulated-LTE-Network#normal-ue-connections).)

```
> ./xim.py -g process
...
WARNING: 2024-01-30 14:48:10 - Cross-process flow: systemd -> /sys/fs/cgroup/memory/kubepods.slice/kubepods-besteffort.slice/memory.limit_in_bytes -> kubelet
WARNING: 2024-01-30 14:48:10 - Cross-process flow: systemd -> /sys/fs/cgroup/pids/kubepods.slice/kubepods-besteffort.slice/pids.max -> kubelet
WARNING: 2024-01-30 14:48:11 - Cross-process flow: containerd-shim -> /tmp/runc-process473358252 -> runc
WARNING: 2024-01-30 14:48:11 - Cross-process flow: 5 -> /run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/b13cb2ca563b809bddb9729b23459b7ddfac84fe89d8426aacfd88040617b268/log.json -> runc:[1:CHILD]
WARNING: 2024-01-30 14:48:11 - Cross-process flow: containerd-shim -> /tmp/runc-process2105527380 -> runc
WARNING: 2024-01-30 14:48:12 - Cross-process flow: calico-node -> /etc/hosts -> java
WARNING: 2024-01-30 14:48:12 - Cross-process flow: containerd-shim -> /tmp/runc-process239751121 -> runc
WARNING: 2024-01-30 14:48:19 - Cross-process flow: containerd-shim -> /tmp/runc-process3591136423 -> runc
WARNING: 2024-01-30 14:48:24 - Cross-process flow: runc -> /sys/fs/cgroup/cpu,cpuacct/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod498f2655_4500_44d7_97db_47f37d5773a8.slice/cri-containerd-69ecec53e07f5c8b640f3ffab3a474c4833f3602bc1a72829e31ce0c6365ae18.scope/cgroup.procs -> kubelet
WARNING: 2024-01-30 14:48:24 - Cross-process flow: <NA> -> /sys/fs/cgroup/cpu,cpuacct/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod498f2655_4500_44d7_97db_47f37d5773a8.slice/cri-containerd-69ecec53e07f5c8b640f3ffab3a474c4833f3602bc1a72829e31ce0c6365ae18.scope/cgroup.procs -> kubelet
WARNING: 2024-01-30 14:48:28 - Cross-process flow: runc:[1:CHILD] -> /proc/self/mountinfo -> containerd-shim
...
```

---

### Internals

xIM uses Sysdig to monitor I/O events -- that is, read(), write() etc. system calls -- of all processes on the host. Sysdig uses eBPF to only add instrumentation needed to track the required information. This makes the monitoring lightweight.

When a write occurs from a process / container / pod, the path at which it occurred is noted. When a read occurs, a check is done to see if any process / container / pod has written to the path previously. If so, the triple of the writer, path, and reader are reported (if they have not previously been output).
