#!/bin/bash

[ "$UID" -eq 0 ] || exec sudo bash "$0" "$@"

# error fix: udisksd[433]: failed to load module mdraid: libbd_mdraid.so.2
apt install libblockdev-mdraid2 -y


# install awesome vim current user
git clone --depth=1 https://github.com/amix/vimrc.git ~/.vim_runtime
sh ~/.vim_runtime/install_awesome_vimrc.sh

  
#############################
#  Install any php Version  #
#############################

# php 5.6
apt install php5.6-fpm php5.6-gd php5.6-mysql php5.6-curl php5.6-xml \
  php5.6-zip php5.6-intl libapache2-mod-php5.6 php5.6-mbstring php5.6-json \
  php5.6-bz2 php5.6 php5.6-cli php5.6-common php5.6-ssh2 php5.6-mcrypt php5.6-sqlite3 \
  php5.6-bcmath php5.6-gmp

# php 7.0  
apt install php7.0-fpm php7.0-gd php7.0-mysql php7.0-curl php7.0-xml \
  php7.0-zip php7.0-intl libapache2-mod-php7.0 php7.0-mbstring php7.0-json \
  php7.0-bz2 php7.0 php7.0-cli php7.0-common php7.0-ssh2 php7.0-mcrypt php7.0-sqlite3 \
  php7.0-bcmath php7.0-gmp

# php 7.3
apt install php7.3-fpm php7.3-gd php7.3-mysql php7.3-curl php7.3-xml \
  php7.3-zip php7.3-intl libapache2-mod-php7.3 php7.3-mbstring php7.3-json \
  php7.3-bz2 php7.3 php7.3-cli php7.3-common php7.3-ssh2 php7.3-sqlite3 \
  php7.3-bcmath php7.3-gmp

# php 7.4
apt install php7.4-fpm php7.4-gd php7.4-mysql php7.4-curl php7.4-xml \
  php7.4-zip php7.4-intl libapache2-mod-php7.4 php7.4-mbstring php7.4-json \
  php7.4-bz2 php7.4 php7.4-cli php7.4-common php7.4-sqlite3 php7.4-bcmath php7.4-gmp

systemctl enable php5.6-fpm php7.0-fpm php7.3-fpm
systemctl enable php7.4-fpm

# standard php version for apache is 7.0
a2dismod php7.3 php5.6 php7.4
a2enmod  php7.0
systemctl restart apache2

# standard php version for system
update-alternatives --set php /usr/bin/php7.3
php -i | grep "Loaded Configuration File"


#######################################
# Install Xserver on rasp Image lite  #
#######################################

apt install --no-install-recommends xserver-xorg -y
apt install raspberrypi-ui-mods xinit firefox-esr-l10n-de piclone -y

# error fix: Error getting user list from org.freedesktop.Accounts: GDBus.Error
apt install accountsservice -y

# error fix
mkdir /var/lib/lightdm/data
chown lightdm:lightdm /var/lib/lightdm/data

# full xserver
# apt install lxde lxde-core lxterminal lxappearanextcloude lightdm raspberrypi-ui-mods -y


####################################
# xrdp - Microsoft Remote Desktop  #
####################################

apt install xrdp -y
service xrdp start
update-rc.d xrdp enable


#######################
#  Install VNC Server #
#######################

apt install acl bc colord colord-data cups cups-browsed cups-client cups-common \
  cups-core-drivers cups-daemon cups-filters cups-filters-core-drivers \
  cups-ipp-utils cups-ppdc cups-server-common libcolorhug2 libfontembed1 libgusb2 \
  libgutenprint-common libgutenprint9 libieee1284-3 liblouis-data liblouis17 \
  liblouisutdml-bin liblouisutdml-data liblouisutdml8 libpoppler82 libqpdf21 \
  libsane libsane-common libyaml-0-2 poppler-utils printer-driver-gutenprint \
  realvnc-vnc-server sane-utils update-inetd -y

systemctl enable vncserver-x11-serviced.service
systemctl start vncserver-x11-serviced.service

# error: Cannot currently show the desktop
# error fix (Display Resulotion 1024x764) with
# raspi-config or this: 

sed -i 's/hdmi_mode.*/hdmi_mode=16/g' /boot/config.txt


#############
#  apache2  #
#############

# AH00111: Config variable ${APACHE_RUN_DIR} is not defined
# DefaultRuntimeDir must be a valid directory, absolute or relative to ServerRoot
# source /etc/apache2/envvars (fixed the error)


##################
#  Apache Sites  #
##################

# enable cgi-bin
cat <<EOF > /etc/apache2/conf-available/cgi-enabled.conf
<IfModule mod_alias.c>
    <IfModule mod_cgi.c>
        Define ENABLE_USR_LIB_CGI_BIN
    </IfModule>

    <IfModule mod_cgid.c>
        Define ENABLE_USR_LIB_CGI_BIN
    </IfModule>

<IfDefine ENABLE_USR_LIB_CGI_BIN>
  ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
  <Directory "/usr/lib/cgi-bin">
    AllowOverride None
    Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch   
    AddHandler cgi-script .cgi .py .pl
# SetHandler cgi-script (all files allowed) 
    Require all granted
  </Directory>
</IfDefine>
</IfModule>

SecRuleEngine On
 <IfModule security2_module>
          Include /usr/share/modsecurity-crs/crs-setup.conf
          Include /usr/share/modsecurity-crs/rules/*.conf
    </IfModule>
EOF
#enable cgi-bin
a2enmod cgid cgi
a2enconf cgi-enabled.conf


################
#   Apache   security#
################

# modsecurity config
rm -rf /usr/share/modsecurity-crs
git clone https://github.com/coreruleset/coreruleset /usr/share/modsecurity-crs
cp /usr/share/modsecurity-crs/crs-setup.conf.example /usr/share/modsecurity-crs/crs-setup.conf
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf 
sed -i "s/SecRuleEngine.*/SecRuleEngine On/g" /etc/modsecurity/modsecurity.conf

# Apache security2 modul config
cat <<EOF >> /etc/apache2/apache2.conf
SecRuleEngine On
 <IfModule security2_module>
          Include /usr/share/modsecurity-crs/crs-setup.conf
          Include /usr/share/modsecurity-crs/rules/*.conf
          ServerTokens Full
          SecServerSignature "Apache/2.2.16 (Unix)"
    </IfModule>

ServerName 127.0.0.1
EOF

################
#   Apache modul      #
################

a2enmod headers security2 proxy_fcgi

# apache2 mod needed for shell in a box
a2enmod proxy_balancer proxy proxy_http


################
#   Apache test scripts     #
################

a2enmod headers security2 proxy_fcgi

# apache2 mod needed for shell in a box
a2enmod proxy_balancer proxy proxy_http

# Python Test
cat <<EOF > /usr/lib/cgi-bin/py_test.py
#!/usr/bin/python
import cgi
cgi.test()
EOF
chmod +x /usr/lib/cgi-bin/py_test.py

# Perl Test
cat <<EOF > /usr/lib/cgi-bin/pl_test.pl
#!/usr/bin/perl
print "Content-type: text/html\n\n";
print "<BODY BGCOLOR=black>\n";
print "<FONT COLOR=white><P>";
print "<tt>\n";
foreach $key (sort keys(%ENV)) {
      print "$key = $ENV{$key}<BR>\n";
}
print "</FONT></BODY>"; 
EOF
chmod +x /usr/lib/cgi-bin/pl_test.pl

# php Test
cat <<EOF > /var/www/html/php_test.php
<?php
phpinfo();
?>
EOF

#PHP Mod fpm/php.ini (Nextcloud config) 
cp /etc/php/7.3/fpm/php.ini /etc/php/7.3/fpm/php.ini_org
sed -i "s/memory_limit = 128M/memory_limit = 512M/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.enable=.*/opcache.enable=1/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.enable_cli=.*/opcache.enable_cli=1/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=8/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=10000/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.memory_consumption=.*/opcache.memory_consumption=128/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.save_comments=.*/opcache.save_comments=1/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.revalidate_freq=.*/opcache.revalidate_freq=1/" /etc/php/7.3/fpm/php.ini


############### 
# jail chroot #
###############

apt install build-essential autoconf automake libtool flex bison debhelper binutils -y
wget https://olivier.sessink.nl/jailkit/jailkit-2.21.tar.gz
tar xvfz jailkit-2.22.tar.gz
cd jailkit-2.22
echo 5 > debian/compat
./debian/rules binary
cd ..
dpkg -i jailkit_2.22-1_*.deb
mkdir /home/jail
chown root:root /home/jail
chmod 0755 /home/jail
/usr/sbin/jk_init -j /home/jail jk_lsh
/usr/sbin/jk_init -j /home/jail sftp
/usr/sbin/jk_init -j /home/jail scp
/usr/sbin/jk_init -j /home/jail ssh
/usr/sbin/jk_init -j /home/jail basicshell editors extendedshell netutils
/usr/sbin/jk_cp -j /home/jail/ /usr/bin/id
/usr/sbin/jk_cp -j /home/jail/ /usr/bin/strace
/usr/sbin/jk_cp -j /home/jail/ /usr/bin/whois
useradd -m julian
# passwd julian
/usr/sbin/jk_jailuser -j /home/jail -s /usr/sbin/jk_lsh -m julian
/usr/sbin/jk_jailuser -m -j /home/jail julian
#sed -i 's/julian/#julian/g' /home/jail/etc/passwd
echo "root:x:0:0:root:/root:/bin/bash" > /home/jail/etc/passwd
echo "julian:x:1002:1002:,,,:/home/julian:/bin/bash" >> /home/jail/etc/passwd
rm -rf /home/jail/etc/jailkit/ 


##############
#  influxdb  #
##############

# with kali = apt install influxdb-client influxdb

# curl -sL https://repos.influxdata.com/influxdb.key | sudo apt-key add -
# echo "deb https://repos.influxdata.com/debian buster stable" | sudo tee /etc/apt/sources.list.d/influxdb.list

apt install influxdb -y
service influxdb start
/bin/systemctl daemon-reload
/bin/systemctl enable influxdb

influx -execute 'CREATE DATABASE influxdb'

cp /etc/influxdb/influxdb.conf /etc/influxdb/influxdb.conf_org
sed -i 's/\[\[collectd\]\]/#\[\[collectd\]\]/g' /etc/influxdb/influxdb.conf
cat <<EOF >> /etc/influxdb/influxdb.conf
[[collectd]]
  enabled = true
  bind-address = "127.0.0.1:25826"
  database = "influxdb"
  typesdb = "/usr/share/collectd/types.db"
EOF


#############
#  grafana  #
#############

# echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
# wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -

apt install grafana -y

service grafana-server start
/bin/systemctl daemon-reload
/bin/systemctl enable grafana-server
update-rc.d grafana-server defaults


###################
# fail2ban config #
###################

# create a fail2ban Nextcloud filter
cat <<EOF >/etc/fail2ban/filter.d/nextcloud.conf
[Definition]
failregex=^{"reqId":".*","remoteAddr":".*","app":"core","message":"Login failed: '.*' \(Remote IP: '<HOST>'\)","level":2,"time":".*"}$
          ^{"reqId":".*","level":2,"time":".*","remoteAddr":".*","user,:".*","app":"no app in context".*","method":".*","message":"Login failed: '.*' \(Remote IP: '<HOST>'\)".*}$
          ^{"reqId":".*","level":2,"time":".*","remoteAddr":".*","user":".*","app":".*","method":".*","url":".*","message":"Login failed: .* \(Remote IP: <HOST>\)".*}$
EOF

# create a fail2ban Nextcloud jail
cat <<EOF >/etc/fail2ban/jail.d/nextcloud.local
[nextcloud]
enabled = true
filter = nextcloud
backend = auto
port = 80,443
protocol = tcp
maxretry = 5
bantime = 3600
findtime = 3600
logpath = /var/www/nextcloud/data/nextcloud.log
[apache-auth]
enabled = true
EOF

cat <<EOF >/etc/fail2ban/jail.local 
[apache-auth]
enabled = true
port    = http,https
filter  = apache-auth
logpath = /var/log/apache*/error*.log
maxretry = 4

[apache-multiport]
enabled   = false
port      = http,https
filter    = apache-auth
logpath   = /var/log/apache*/error*.log
maxretry  = 4

[apache-noscript]
enabled = true
port    = http,https
filter  = apache-noscript
logpath = /var/log/apache*/error*.log
maxretry = 4

[apache-overflows]
enabled = true
port    = http,https
filter  = apache-overflows
logpath = /var/log/apache*/error*.log
maxretry = 10

[apache-nohome]
enabled = true
port = http,https
filter = apache-nohome
logpath = /var/log/apache*/error*.log
maxretry = 5

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache*/access*.log
maxretry = 3

[webmin-auth]
enabled = true

[squid]
enabled = true

[phpmyadmin-syslog]
enabled = true
EOF


######################
#   install unbound  #
######################

apt install unbound -y
wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
chown unbound:unbound /var/lib/unbound/root.hints

# update root.hints
wget -O /usr/local/bin/autoupdatelocalroot https://raw.githubusercontent.com/henosch/pi4/main/autoupdatelocalroot
chmod 755 /usr/local/bin/autoupdatelocalroot
echo -e "$(crontab -l)\n20 4 * * 0    /usr/local/bin/autoupdatelocalroot" | crontab -u mike -
wget -O /usr/local/bin/updateunboundconf https://raw.githubusercontent.com/henosch/pi4/main/updateunboundconf
chmod 755 /usr/local/bin/updateunboundconf

cat <<EOF >> /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    # If no logfile is specified, syslog is used
    # logfile: "/var/log/unbound/unbound.log"
    verbosity: 0

    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes

    # May be set to yes if you have IPv6 connectivity
    do-ip6: no

    # Use this only when you downloaded the list of primary root servers!
    root-hints: "/var/lib/unbound/root.hints"

    # Trust glue only if it is within the servers authority
    harden-glue: yes

    # Require DNSSEC data for trust-anextcloudhored zones, if such data is absent, the zone becomes BOGUS
    harden-dnssec-stripped: yes

    # Don't use Capitalization randomization as it known to cause DNSSEC issues sometimes
    # see https://discourse.pi-hole.net/t/unbound-stubby-or-dnscrypt-proxy/9378 for further details
    use-caps-for-id: no

    # Reduce EDNS reassembly buffer size.
    # Suggested by the unbound man page to reduce fragmentation reassembly problems
    edns-buffer-size: 1472

    # TTL bounds for cache
    cache-min-ttl: 3600
    cache-max-ttl: 86400

    # Perform prefetching of close to expired message cache entries
    # This only applies to domains that have been frequently queried
    prefetch: yes

    # One thread should be sufficient, can be inextcloudreased on beefy machines
    num-threads: 1

    # Ensure kernel buffer is large enough to not lose messages in traffic spikes
    so-rcvbuf: 1m

    # Ensure privacy of local IP ranges
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
EOF

systemctl restart unbound
echo "nameserver 159.69.114.157" > /etc/resolv.conf

# test it
#dig google.com @127.0.0.1 -p 5335
#dig sigfail.verteiltesysteme.net @127.0.0.1 -p 5335
#dig sigok.verteiltesysteme.net @127.0.0.1 -p 5335


#####################
#  install pi-hole  #
#####################

mkdir /etc/pihole

# setupVars.conf
cat <<EOF > /etc/pihole/setupVars.conf
WEBPASSWORD=ecdca4c1892c120b16105c4c99e1d80c9363cd23b209d830c4660777552a51e6
DNSMASQ_LISTENING=local
PIHOLE_INTERFACE=eth0
IPV4_ADDRESS=192.168.11.29/24
IPV6_ADDRESS=2001:a61:115a:4c01:b018:a0ef:1872:6f3f
PIHOLE_DNS_1=127.0.0.1#5335
PIHOLE_DNS_2=127.0.0.1#5335
QUERY_LOGGING=true
INSTALL_WEB_SERVER=false
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=false
CACHE_SIZE=10000
BLOCKING_ENABLED=true
EOF

# white list
cat <<EOF > /etc/pihole/whitelist.txt
raw.githubusercontent.com
device-metrics-us-2.amazon.com
fls-eu.amazon.de
mytools.management
connectivitycheck.gstatic.com
in.appcenter.ms
s3.amazonaws.com
v.firebog.net
fritz.box
bnc.lt
de.ioam.de
EOF

# adlists
cat <<EOF > /etc/pihole/adlists.list
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
http://localhost/adblock.hosts
https://dl.dropboxusercontent.com/s/j9vfm2x6o9qj7ox/hosts
https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt
https://v.firebog.net/hosts/AdguardDNS.txt
https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext
https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list
https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list
https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/combined_disguised_trackers_justdomains.txt
https://github.com/RPiList/specials/blob/master/Blocklisten/Corona-Blocklist
https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe
https://raw.githubusercontent.com/henosch/my-pihole-lists/master/block_google_updates.txt
EOF

# pihole-FTL.conf
cat <<EOF > /etc/pihole/pihole-FTL.conf
PRIVACYLEVEL=0
IGNORE_LOCALHOST=yes
AAAA_QUERY_ANALYSIS=no
EOF

# AdBlock Lists (EasyList, EasyPrivacy, / Social Blocking)
cat <<EOF > /etc/pihole/myblocklist.sh
#!/bin/sh
curl -s -L https://easylist.to/easylist/easylist.txt https://easylist.to/easylist/easyprivacy.txt \\
 https://easylist.to/easylist/fanboy-social.txt > adblock.unsorted
 
# Look for: ||domain.tld^
sort -u adblock.unsorted | grep ^\|\|.*\^$ | grep -v \/ > adblock.sorted
 
# Remove extra chars and put list under lighttpd web root
sed 's/[\|^]//g' < adblock.sorted > /var/www/html/adblock.hosts
 
# Remove files we no longer need
rm adblock.unsorted adblock.sorted
sudo chown pihole:pihole -R /etc/pihole/
EOF

chmod 755 /etc/pihole/myblocklist.sh

# update AdBlock Lists (EasyList, EasyPrivacy, / Social Blocking)
cat <<EOF > /etc/pihole/update_myblocklist.sh
#!/bin/sh
/etc/pihole/myblocklist.sh
pihole -g
EOF

chmod 755 /etc/pihole/update_myblocklist.sh
echo -e "$(crontab -l)\n30 2 * * 6    pihole    /etc/pihole/update_myblocklist.sh" | crontab -u root -
echo -e "$(crontab -l)\n30 2 * * 7    /usr/local/bin/pihole updatePihole" | crontab -u root -
chown pihole:pihole -R /etc/pihole/ 
sh /etc/pihole/myblocklist.sh

# pihole without inside http server. We use apache 2
curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended --disable-install-webserver
usermod -a -G pihole www-data

# Statistics 
cat <<EOF > /etc/pihole/uniq_urls.sh
#!/bin/bash
# Check all lists for unique ones and show the percentage

[ "$UID" -eq 0  ] || exec sudo bash "$0" "$@"

cd /etc/pihole/
cat *.domains | sort | uniq -u > all_adlist_urls_sorted_unique.txt

# Result
T1=$(cat *.domains | wc -l)
T2=$(cat all_adlist_urls_sorted_unique.txt | wc -l)
S=$(python -c "p = $T2 / $T1 * 100; print(p)")
printf "URLs total:		%10d\n" $T1
printf "URLs unique:	%10d\n" $T2
printf "Percentage:	  %8.1f %%\n" $S
EOF
chmod +x /etc/pihole/uniq_urls.sh

# useful commands
# sqlite3 /etc/pihole/gravity.db "SELECT domain FROM vw_blacklist;"
# sqlite3 /etc/pihole/gravity.db "SELECT domain FROM vw_whitelist;"
# sqlite3 /etc/pihole/gravity.db "SELECT domain FROM vw_regex_blacklist;"
# sqlite3 /etc/pihole/gravity.db "SELECT domain FROM vw_regex_whitelist;"
# sqlite3 /etc/pihole/gravity.db "SELECT address FROM adlist;"
# sqlite3 /etc/pihole/gravity.db ".schema domainlist"
# sqlite3 /etc/pihole/gravity.db ".schema"


#######################
# install rpi monitor #
#######################

# apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 2C0D3C0F
# wget http://goo.gl/vewCLL -O /etc/apt/sources.list.d/rpimonitor.list

apt install rpimonitor -y
conf_file="/etc/rpimonitor/data.conf"
cp $conf_file /etc/rpimonitor/data.conf_org
sed -i 's/#inextcloudlude=\/etc\/rpimonitor\/template\/network.conf/inextcloudlude=\/etc\/rpimonitor\/template\/network.conf/g' $conf_file
cp /usr/share/rpimonitor/web/addons/top3/top3.cron /etc/cron.d/top3
sed -i 's/#web.addons.5.name\=Top3/web.addons.5.name\=Top3/g' $conf_file
sed -i 's/#web.addons.5.addons\=top3/web.addons.5.addons\=top3/g' $conf_file
first="s/#web.status.1.content.1.line.4\=InsertHTML(\"\/addons\/top3\/top3.html\")/"
second="web.status.1.content.1.line.4\=InsertHTML(\"\/addons\/top3\/top3.html\")/g "
sed -i $first$second /etc/rpimonitor/template/cpu.conf

# enable all network settings
sed -i '12,42s/^#//' /etc/rpimonitor/template/network.conf

# disable intern webserver
sed -i 's/^#daemon.noserver\=1/daemon.noserver\=1/g' /etc/rpimonitor/daemon.conf

cat <<EOF >> /etc/cron.d/rpimonitor
# run at 03:05 to update local repository database
05 03 * * * root /usr/bin/apt-get update > /dev/null 2>&1
 
# run at 03:10 to update status
10 03 * * * root /usr/share/rpimonitor/scripts/updatePackagesStatus.pl
EOF

cat <<EOF >> /etc/cron.d/top3
* * * * * root cd /usr/share/rpimonitor/web/addons/top3; ./top3 > top3.html
EOF

/etc/init.d/rpimonitor update
/etc/init.d/rpimonitor install_auto_package_status_update


##################
# install webmin #
##################

apt install libauthen-pam-perl apt-show-versions libio-pty-perl
wget http://prdownloads.sourceforge.net/webadmin/webmin_1.974_all.deb
dpkg --install webmin_1.974_all.deb


##############
# sellinabox #
##############

# shellinabox config file
cp /etc/default/shellinabox /etc/default/shellinabox_org
cat <<EOF > /etc/default/shellinabox
SHELLINABOX_DAEMON_START=1
SHELLINABOX_PORT=8700
SHELLINABOX_ARGS="--no-beep --localhost-only --disable-ssl -s /:LOGIN"
EOF

# terminal white on black
mv /etc/shellinabox/options-enabled/00+Black\ on\ White.css /etc/shellinabox/options-enabled/00_Black\ on\ White.css \
 && mv /etc/shellinabox/options-enabled/00_White\ On\ Black.css /etc/shellinabox/options-enabled/00+White\ On\ Black.css


# backup pihole with rclone
curl https://rclone.org/install.sh | sudo bash
curl https://raw.githubusercontent.com/henosch/rclone-backup/master/install.sh | sudo bash
