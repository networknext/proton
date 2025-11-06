#!/bin/sh

# clean out any old journalctl logs so we have space to do stuff

sudo journalctl --vacuum-size 10M

# install necessary packages

sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt autoremove -y
sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt update -y
sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt full-upgrade -y
sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt install libcurl3-gnutls-dev build-essential vim wget libsodium-dev flex bison clang unzip libc6-dev-i386 gcc-12 dwarves libelf-dev pkg-config m4 libpcap-dev net-tools -y
sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt autoremove -y

# install libxdp and libbpf from source

cd ~
wget https://github.com/xdp-project/xdp-tools/releases/download/v1.5.5/xdp-tools-1.5.5.tar.gz
tar -zxf xdp-tools-1.5.5.tar.gz
cd xdp-tools-1.5.5
./configure
make -j && sudo make install

cd lib/libbpf/src
make -j && sudo make install
sudo ldconfig
cd /

# apt update and upgrade is sometimes necessary

sudo apt update -y && sudo apt upgrade -y

# IMPORTANT: if we are not running a 6.5 kernel, upgrade the kernel. we need ubuntu 22.04 LTS with linux kernel 6.5 *at minimum*

major=$(uname -r | awk -F '.' '{print $1}')
minor=$(uname -r | awk -F '.' '{print $2}')

echo linux kernel version is $major.$minor

if [[ $major -lt 6 ]]; then
  echo "upgrading linux kernel to 6.5... please run setup again on this machine after it reboots"
  sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt install linux-generic-hwe-22.04 -y
  sudo reboot
fi

# if we need to reboot, it's best to do it now before we try to install linux headers because the kernel version may change

if [ -f /var/run/reboot-required ]; then
    echo "rebooting. please run setup again on this machine after it reboots"
    sudo reboot
fi

# setup linux tools, headers and vmlinux BTF file needed for bpf. this requires 6.5+ linux kernel to work

sudo NEEDRESTART_SUSPEND=1 apt install dwarves linux-headers-`uname -r` linux-tools-`uname -r` -y

sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/

# install proton module

make
sudo mkdir -p /lib/modules/`uname -r`/kernel/net/proton
sudo mv proton.ko /lib/modules/`uname -r`/kernel/net/proton

# setup proton module to load on reboot

cd ~
cp /etc/modules ~
echo "proton" >> modules.txt
sudo mv modules.txt /etc/modules
sudo depmod
