# pi4 debian 10 installation 

+ ssh pi@raspberrypi
+ sudo -i
+ passwd
+ passwd pi

+ adduser $suname (your own user) 
+ adduser $suname sudo
+ exit
+ exit
+ ssh $suname@raspberrypi
+ sudo -i

# Set your own data with vars
```bash
cat <<EOF > /root/custom_vars
# you must set skip=owner_vars
skip=owner_vars
#
suname=your user
ssk=cat id_rsa.pub (write here your sshkey) 
timez=your timezone
ss="your WLAN ID"
ssp=WLAN password
wcountry=WLAN Country e.g DE
jail_user=jail user
jail_pw=jail password
appw=htaccess user 
ddns1=dyndns1
ddns2=dyndns2
ddns3=dyndns3
ddns4=dyndns4
ddns5=dyndns5
local_net=192.168.178 only 3 blocks (your localnet) 
nas_pw=my nas password
ssl_email=letsencrypt email
gb=remote server ssh
root_pw=mysql root password
sql_user=mysql user
sql_user_pw=mysql user password
database=nextcloud (database name) 
fritz_pw=fritz.box login password
fritz_coll=collect password (fritz.box) 
smb_pw=your samba user password
# adminer language (default english)
adminer=latest.php
pi_hole_pw=your pihole password
IPV6_ADDRESS=your server ipv6 ip
IPV4_ADDRESS=your server ipv4 ip
EOF
```
# Script owner custom vars (you must set it) 
+ The script owner custom vars are skipped with skip=owner_vars

# install first 
curl https://raw.githubusercontent.com/henosch/pi4/main/01_install.sh | sudo bash

# install second 
curl https://raw.githubusercontent.com/henosch/pi4/main/02_install.sh | sudo bash
