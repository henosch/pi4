#!/usr/bin/bash
# automatic root
[ "$UID" -eq 0 ] || exec sudo bash "$0" "$@"

# if [ $EUID -ne 0 ]; then
#   echo "$0 is not running as root. Try using sudo."
#   exit 2
# fi

####################
# sudoers settings #
####################

sed -i 's/NOPASSWD/PASSWD/g' /etc/sudoers.d/010_pi-nopasswd
echo "mike ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/010_pi-nopasswd
service sudo restart


#################
# sshd settings #
#################

mkdir -p /home/mike/.ssh && chmod 700 .ssh
cat <<EOF >/home/mike/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKgzf3yRLgztIX0GL5uJYSmsudJdgeGK4tXdt94g+quW mike@localhost
EOF
chmod 600 .ssh/authorized_keys
chown mike:mike -R /home/mike/.ssh

sed -i 's/#Port 22/Port 2022/g' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication/PubkeyAuthentication/g' /etc/ssh/sshd_config
# sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 60/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 240/g' /etc/ssh/sshd_config


################
# set timezone #
################

timedatectl set-timezone Europe/Berlin

##########
# vi fix #
##########

cat <<EOF > /home/mike/.vimrc
:set timeout ttimeoutlen=100 timeoutlen=5000
:set term=builtin_ansi
:set nocompatible
:set backspace=2
EOF
# syntax on

cat <<EOF > /root/.vimrc
:set timeout ttimeoutlen=100 timeoutlen=5000
:set term=builtin_ansi
:set nocompatible
:set backspace=2
EOF
# syntax on


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
country=DE

network={
        ssid="Tut Busse das Ende ist nah"
        psk=dd3ccd7895815d3a38f8a336968e8c4b419f6e517e70a02298661cf443a8d253
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

# The PI Server becomes a name server
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

apt update -y && apt upgrade -y

echo "nameserver 159.69.114.157" > /etc/resolv.conf

apt install apache2 mariadb-server zip unzip build-essential \
  apt-transport-https lsb-release npm git cifs-utils whois \
  python-pip libxml2-dev libxslt1-dev collectd dirmngr  \
  sarg webalizer samba-common-bin fail2ban shellinabox \
  libmariadb-dev-compat libmariadb-dev libapache2-mod-security2 \
  php-apcu imagemagick php-imagick strace samba smbclient locate libsqlite3-dev \
  python3-pip python3-cffi nodejs vim lynx youtube-dl byobu ranger wajig \
  awstats libgeo-ip-perl libgeo-ipfree-perl modsecurity-crs rclone -y
  
# config wajig
ln -s /usr/bin/wajig /usr/bin/apt2


# config byobu
sed -i 's/exec "\$SHELL"/exec "\$SHELL" \-\-login/g'  /usr/bin/byobu-shell
sed -i 's/exec \/bin\/sh/exec \/bin\/bash \-\-login/g'  /usr/bin/byobu-shell
echo "set -g status off" >>~/.byobu/.tmux.conf

# link sh to bash
echo "dash dash/sh boolean false" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure dash

# start 
byobu-enable
reboot
