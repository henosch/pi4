#!/usr/bin/bash
# automatic root
# [ "$UID" -eq 0 ] || exec sudo bash "$0" "$@"

if [ $EUID -ne 0 ]; then
   echo "$0 is not running as root. Try using sudo."
  exit 2
fi

# custom private vars
# used in this script: 
#
# suname=username
# ssk=cat id_rsa.pub and write here
# timez=your timezone
# ss="WLAN ID"
# ssp=WLAN password

# use your custom vars
. /root/custom_vars

####################
# sudoers settings #
####################

sed -i 's/NOPASSWD/PASSWD/g' /etc/sudoers.d/010_pi-nopasswd
echo "$suname ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/010_pi-nopasswd
deluser pi sudo


#################
# sshd settings #
#################

mkdir -p /home/$suname/.ssh && chmod 700 .ssh
cat <<EOF >/home/$suname/.ssh/authorized_keys
$ssk
EOF
chmod 600 .ssh/authorized_keys
chown $suname:$suname -R /home/$suname/.ssh

sed -i 's/#Port 22/Port 2022/g' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication/PubkeyAuthentication/g' /etc/ssh/sshd_config
# sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 60/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 240/g' /etc/ssh/sshd_config


################
# set timezone #
################

timedatectl set-timezone $timez


###############
# wlan config #
###############

cat <<EOF >> /etc/network/interfaces
allow-hotplug wlan0
iface wlan0 inet manual
EOF

cat <<EOF >> /etc/wpa_supplicant/wpa_supplicant-wlan0.conf
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=$wcountry

network={
        ssid="$ss"
        psk=$ssp
        key_mgmt=WPA-PSK
}
EOF

# Password is encrypted
# wpa_passphrase "WLAN-SSID" "WLAN-PASSWORT" >> /etc/wpa_supplicant/wpa_supplicant-wlan0.conf

# rfkill list all
rfkill unblock 0
killall wpa_supplicant
systemctl enable wpa_supplicant@wlan0.service
systemctl start wpa_supplicant@wlan0.service

# config test
# wpa_supplicant -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant-wlan0.conf


###############
# needed repo #
###############

# The PI Server becomes a temp name server
echo "nameserver 159.69.114.157" > /etc/resolv.conf

# php
wget -q https://packages.sury.org/php/apt.gpg -O- | apt-key add -  
echo "deb https://packages.sury.org/php/ buster main" | tee /etc/apt/sources.list.d/php.list

# grafana
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list

# influx
curl -sL https://repos.influxdata.com/influxdb.key | sudo apt-key add -
echo "deb https://repos.influxdata.com/debian buster stable" | sudo tee /etc/apt/sources.list.d/influxdb.list

# fritzctl
# wget -qO - https://api.bintray.com/users/bpicode/keys/gpg/public.key | apt-key add -
# echo "deb https://dl.bintray.com/bpicode/fritzctl_deb buster main" | tee -a /etc/apt/sources.list

# rpi
wget http://goo.gl/vewCLL -O /etc/apt/sources.list.d/rpimonitor.list
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 2C0D3C0F


#####################
# recommend package #
#####################

# Newer kernel available
# needrestart -k
# remove needrestart, because kernel message pop up every time

apt update -y && apt upgrade -y

echo "nameserver 159.69.114.157" > /etc/resolv.conf

apt install apache2 mariadb-server zip unzip build-essential \
  apt-transport-https lsb-release npm git cifs-utils whois \
  python-pip libxml2-dev libxslt1-dev collectd dirmngr  \
  sarg webalizer fail2ban shellinabox \
  libmariadb-dev-compat libmariadb-dev libapache2-mod-security2 \
  php-apcu imagemagick php-imagick strace locate libsqlite3-dev \
  python3-pip python3-cffi nodejs vim lynx youtube-dl byobu ranger wajig \
  awstats libgeo-ip-perl libgeo-ipfree-perl rclone -y
  

# we want from https://github.com/coreruleset/coreruleset the ruleset
# if ! dpkg-query -W -f='${Status}' modsecurity-crs | grep "ok installed"; then apt install modsecurity-crs -y; fi
if dpkg-query -W -f='${Status}' modsecurity-crs | grep "ok installed"; then apt remove modsecurity-crs -y; fi


# install awesome vim for root
git clone --depth=1 https://github.com/amix/vimrc.git /root/.vim_runtime
cp /root/.vim_runtime/vimrcs/basic.vim /root/.vimrc

# install awesome vim for $suname
git clone --depth=1 https://github.com/amix/vimrc.git /home/$suname/.vim_runtime
cp /home/$suname/.vim_runtime/vimrcs/basic.vim /home/$suname/.vimrc
 
##########
# vi fix #
##########

cat <<EOF >> /home/$suname/.vimrc
:set timeout ttimeoutlen=100 timeoutlen=5000
:set term=builtin_ansi
:set nocompatible
EOF
sed -i "s/backspace=.*/backspace=2/g" /root/.vimrc
chown $suname:$suname -R /home/$suname
# syntax on

cat <<EOF >> /root/.vimrc
:set timeout ttimeoutlen=100 timeoutlen=5000
:set term=builtin_ansi
:set nocompatible
EOF
sed -i "s/backspace=.*/backspace=2/g" /home/$suname/.vimrc
# syntax on


# config wajig
ln -s /usr/bin/wajig /usr/bin/apt2

# link sh to bash
echo "dash dash/sh boolean false" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure dash

# config byobu
sed -i 's/exec "\$SHELL"/exec "\$SHELL" \-\-login/g'  /usr/bin/byobu-shell
sed -i 's/exec \/bin\/sh/exec \/bin\/bash \-\-login/g'  /usr/bin/byobu-shell
echo "set -g status off" >>/home/$suname/.byobu/.tmux.conf

# start 
sudo -u $suname /usr/bin/byobu-enable

reboot
