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
# jail_user=jail user
# jail_pw=jail password
# appw=htaccess user 
# ddns1=dyndns1
# ddns2=dyndns2
# ddns3=dyndns3
# ddns4=dyndns4
# ddns5=dyndns5
# ddns_srv=dyndns update server
# local_net=192.168.178 (your localnet) 
# nas_pw=my nas password
# ssl_email=letsencrypt email
# gb=remote server ssh
# root_pw=mysql root password
# sql_user=mysql user
# sql_user_pw=mysql user password
# database=nextcloud (database name) 
# fritz_pw=fritz.box login password
# fritz_coll=collect password (fritz.box) 
# smb_pw=your samba user password
# pi_hole_pw=your pihole password
# IPV6_ADDRESS=your server ipv6 ip
# IPV4_ADDRESS=your server ipv4 ip

# use your custom vars
. /root/custom_vars

# error fix: udisksd[433]: failed to load module mdraid: libbd_mdraid.so.2
# apt install libblockdev-mdraid2 -y


##############
# my Network #
##############

if [ -z "$skip" ]
	then
cat <<EOF >>/etc/hosts
$local_net.254	fritz.box
$local_net.150	nas
$local_net.1    macsdero
$local_net.21	oneplus6t
$local_net.22	drucker
$local_net.23	cubot
$local_net.26	redmipro
$local_net.25	chromecast
$local_net.27   hue
$local_net.28	boombox
$local_net.32	firestick
EOF
      exit
fi

################
# mount my NAS #
################

if [ -z "$skip" ]
	then
mkdir /mnt/nas
mount -t cifs //$local_net.150/freeway/Linux/pi /mnt/nas -o username=$suname,password=$nas_pw,rw,vers=1.0
echo "//$local_net.150/freeway/Linux/pi /mnt/nas cifs  username=$suname,password=$nas_pw,vers=1.0    0    0" >> /etc/fstab
      exit
fi

############
# Language #
############

if [ -z "$skip" ]
	then
sed -i "s/en_GB.UTF-8 UTF-8/# en_GB.UTF-8 UTF-8/g" /etc/locale.gen
sed -i "s/# de_DE ISO-8859-1/de_DE ISO-8859-1/g" /etc/locale.gen
sed -i "s/# de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/g" /etc/locale.gen
dpkg-reconfigure -f noninteractive locales
	exit
fi


#############################
#  Install any php Version  #
#############################

echo "nameserver 159.69.114.157" > /etc/resolv.conf
# php 5.6
apt install php5.6-fpm php5.6-gd php5.6-mysql php5.6-curl php5.6-xml \
  php5.6-zip php5.6-intl libapache2-mod-php5.6 php5.6-mbstring php5.6-json \
  php5.6-bz2 php5.6 php5.6-cli php5.6-common php5.6-ssh2 php5.6-mcrypt php5.6-sqlite3 \
  php5.6-bcmath php5.6-gmp -y

echo "nameserver 159.69.114.157" > /etc/resolv.conf
# php 7.0  
apt install php7.0-fpm php7.0-gd php7.0-mysql php7.0-curl php7.0-xml \
  php7.0-zip php7.0-intl libapache2-mod-php7.0 php7.0-mbstring php7.0-json \
  php7.0-bz2 php7.0 php7.0-cli php7.0-common php7.0-ssh2 php7.0-mcrypt php7.0-sqlite3 \
  php7.0-bcmath php7.0-gmp -y

echo "nameserver 159.69.114.157" > /etc/resolv.conf
# php 7.3
apt install php7.3-fpm php7.3-gd php7.3-mysql php7.3-curl php7.3-xml \
  php7.3-zip php7.3-intl libapache2-mod-php7.3 php7.3-mbstring php7.3-json \
  php7.3-bz2 php7.3 php7.3-cli php7.3-common php7.3-ssh2 php7.3-sqlite3 \
  php7.3-bcmath php7.3-gmp -y

echo "nameserver 159.69.114.157" > /etc/resolv.conf
# php 7.4
apt install php7.4-fpm php7.4-gd php7.4-mysql php7.4-curl php7.4-xml \
  php7.4-zip php7.4-intl libapache2-mod-php7.4 php7.4-mbstring php7.4-json \
  php7.4-bz2 php7.4 php7.4-cli php7.4-common php7.4-sqlite3 php7.4-bcmath php7.4-gmp -y
  
echo "nameserver 159.69.114.157" > /etc/resolv.conf
# php 8.0
 apt install php8.0-fpm php8.0-gd php8.0-mysql php8.0-curl php8.0-xml \
  php8.0-zip php8.0-intl libapache2-mod-php8.0 php8.0-mbstring \
  php8.0-bz2 php8.0 php8.0-cli php8.0-common php8.0-ssh2 php8.0-mcrypt php8.0-sqlite3 \
  php8.0-bcmath php8.0-gmp -y

systemctl enable php5.6-fpm php7.0-fpm php7.3-fpm php7.4-fpm php8.0-fpm

# standard php version for apache is 7.0
a2dismod php5.6 php7.3 php7.4 php8.0
a2enmod  php7.0
systemctl restart apache2

# standard php version for system
update-alternatives --set php /usr/bin/php7.3
php -i | grep "Loaded Configuration File"


#######################################
# Install Xserver on rasp Image lite  #
#######################################

echo "nameserver 159.69.114.157" > /etc/resolv.conf
apt install --no-install-recommends xserver-xorg \
  raspberrypi-ui-mods xinit firefox-esr-l10n-de piclone -y

# error fix: Error getting user list from org.freedesktop.Accounts: GDBus.Error
apt install accountsservice

# error fix
mkdir /var/lib/lightdm/data
chown lightdm:lightdm /var/lib/lightdm/data

# full xserver
# apt install lxde lxde-core lxterminal lxappearanextcloude lightdm raspberrypi-ui-mods -y


####################################
# xrdp - Microsoft Remote Desktop  #
####################################

echo "nameserver 159.69.114.157" > /etc/resolv.conf
apt install xrdp -y
service xrdp start
update-rc.d xrdp enable


#######################
#  Install VNC Server #
#######################

echo "nameserver 159.69.114.157" > /etc/resolv.conf
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

sed -i 's/#hdmi_mode.*/hdmi_mode=16/g' /boot/config.txt
sed -i 's/#hdmi_force_hotplug/hdmi_force_hotplug/g' /boot/config.txt
sed -i 's/#hdmi_group.*/hdmi_group=2/g' /boot/config.txt


#############
#  apache2  #
#############

# AH00111: Config variable ${APACHE_RUN_DIR} is not defined
# DefaultRuntimeDir must be a valid directory, absolute or relative to ServerRoot
# source /etc/apache2/envvars (fixed the error)


##################
#  Apache Sites  #
##################

##################
# enable cgi-bin #
##################

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

<IfModule security2_module>
	SecRuleEngine On
</IfModule>

<IfModule mod_rewrite.c>
	RewriteEngine on
	RewriteCond %{SERVER_NAME} =%{SERVER_NAME}
	RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</IfModule>

EOF
# disable old config serve-cgi-bin
a2disconf serve-cgi-bin

#enable cgi-bin
a2enmod cgid cgi
a2enconf cgi-enabled.conf


#############################
# Standard Website - $ddns1 #
#############################

cat <<EOF >/etc/apache2/sites-available/$ddns1.conf
<VirtualHost *:80>
  ServerName $ddns1
  ServerAdmin webmaster@localhost
    
  DocumentRoot /var/www/html

  ProxyPassMatch "^/(.*\\.php(/.*)?)\$" "unix:/var/run/php/php7.3-fpm.sock|fcgi://localhost/var/www/html"
  
  LogLevel warn
  ErrorLog \${APACHE_LOG_DIR}/error_$ddns1.log
  CustomLog \${APACHE_LOG_DIR}/access_$ddns1.log combined

<Directory />
  Options -Indexes +FollowSymLinks +MultiViews
  AllowOverride All
  Require all granted
</Directory>

<Location /adminer.php>
  Authtype Basic
  Authname "Password Required"
  AuthUserFile /etc/apache2/.htpasswd
  Require user $appw
  Require ip $local_net.
  Require forward-dns $ddns1
  SecRuleEngine Off
</Location>

<Location /php_test.php>
  Authtype Basic
  Authname "Password Required"
  AuthUserFile /etc/apache2/.htpasswd
  Require user $appw
  Require ip $local_net.
  Require forward-dns $ddns1
  SecRuleEngine Off
</Location>

<IfModule security2_module>
	SecRuleEngine On
</IfModule>

<IfModule mod_rewrite.c>
	RewriteEngine on
	RewriteCond %{SERVER_NAME} =%{SERVER_NAME}
	RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</IfModule>

#<FilesMatch \\.php$>
  # Apache 2.4.10+ can proxy to unix socket
  # SetHandler "proxy:unix:/var/run/php/php5.6-fpm.sock|fcgi://localhost/"
#</FilesMatch>

Header unset X-Powered-By
Header always set Content-Security-Policy "default-src https: data: 'self' 'unsafe-inline' 'unsafe-eval'; form-action https: 'self'; referrer origin;"
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options sameorigin
Header always set X-XSS-Protection "1; mode=block"

</VirtualHost>
EOF
wget -O /var/www/html/adminer.php https://www.adminer.org/$adminer
a2ensite $ddns1.conf


#############################
# Pi Control site - $ddns3  #
#############################

cat <<EOF >/etc/apache2/sites-available/$ddns3_pic.conf
<VirtualHost *:80>
  ServerName $ddns3 
  ServerAdmin webmaster@localhost
    
  DocumentRoot /var/www/html/pic

  ProxyPassMatch "^/(.*\\.php(/.*)?)\$" "unix:/var/run/php/php7.0-fpm.sock|fcgi://localhost/var/www/html/pic"
   
  LogLevel warn 
  ErrorLog \${APACHE_LOG_DIR}/error_$ddns3_pic.log
  CustomLog \${APACHE_LOG_DIR}/access_$ddns3_pic.log combined

<Directory "/var/www/html/pic">
  DirectoryIndex status.html index.php index.html index.htm
  Options -Indexes +FollowSymLinks +MultiViews
  Authtype Basic
  Authname "Password Required"
  AuthUserFile /etc/apache2/.htpasswd
  Require user $appw
  Require ip $local_net.
  Require forward-dns $ddns1
</Directory>

<IfModule security2_module>
	SecRuleEngine On
</IfModule>

<IfModule mod_rewrite.c>
	RewriteEngine on
	RewriteCond %{SERVER_NAME} =%{SERVER_NAME}
	RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</IfModule>
    
#<FilesMatch \\.php$>
  # Apache 2.4.10+ can proxy to unix socket
  # SetHandler "proxy:unix:/var/run/php/php5.6-fpm.sock|fcgi://localhost/"
#</FilesMatch>

Header unset X-Powered-By
Header always set Content-Security-Policy "default-src https: data: 'self' 'unsafe-inline' 'unsafe-eval'; form-action https: 'self'; referrer origin;"
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options sameorigin
Header always set X-XSS-Protection "1; mode=block"

</VirtualHost>
EOF
# enable Pi Control site
a2ensite $ddns3_pic.conf


#######################################
# apache site for rpimonitor - $ddns2 #
#######################################

cat <<EOF >/etc/apache2/sites-available/$ddns2_rpi.conf
<VirtualHost *:80>
  ServerName $ddns2
  ServerAdmin webmaster@localhost
  DocumentRoot "/usr/share/rpimonitor/web"

  LogLevel warn
  ErrorLog \${APACHE_LOG_DIR}/error_$ddns2_rpi.log
  CustomLog \${APACHE_LOG_DIR}/access_$ddns2_rpi.log combined
  #Alias /rpim/ "/usr/share/rpimonitor/web"

<Directory "/usr/share/rpimonitor/web">
  DirectoryIndex status.html index.php index.html index.htm
  Options -Indexes +FollowSymLinks +MultiViews
  Authtype Basic
  Authname "Password Required"
  AuthUserFile /etc/apache2/.htpasswd
  Require user $appw
  Require ip $local_net.
  Require forward-dns $ddns1
</Directory>

<IfModule security2_module>
	SecRuleEngine On
</IfModule>

<IfModule mod_rewrite.c>
	RewriteEngine on
	RewriteCond %{SERVER_NAME} =%{SERVER_NAME}
	RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</IfModule>
  
</VirtualHost>

Header unset X-Powered-By
Header always set Content-Security-Policy "default-src https: data: 'self' 'unsafe-inline' 'unsafe-eval'; form-action https: 'self'; referrer origin;"
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options sameorigin
Header always set X-XSS-Protection "1; mode=block"
EOF
# enable site for rpimonitor
a2ensite $ddns2_rpi.conf


######################
# nextcloud - $ddns4 #
######################

cat <<EOF >/etc/apache2/sites-available/$ddns4_nc.conf
<VirtualHost *:80>
  ServerName $ddns4
  ServerAdmin webmaster@localhost

  DocumentRoot /var/www/nextcloud

# ProxyErrorOverride on
# ProxyPassMatch "^/(.*\\.php(/.*)?)\$" "unix:/var/run/php/php7.3-fpm.sock|fcgi://localhost/var/www/nextcloud"

# <If "-f %{SCRIPT_FILENAME}">
# SetHandler "proxy:unix:/run/php/php7.3-fpm.nextcloud.sock|fcgi://localhost"
# </If>

  LogLevel warn
  ErrorLog \${APACHE_LOG_DIR}/error_$ddns4_nextcloud.log
  CustomLog \${APACHE_LOG_DIR}/access_$ddns4_nextcloud.log combined

<Directory /var/www/nextcloud>
  Options -Indexes +FollowSymLinks
  AllowOverride All
  Require all granted

  SetEnv HOME /var/www/nextcloud
  SetEnv HTTP_HOME /var/www/nextcloud

  Redirect 301 /.well-known/carddav /remote.php/dav
  Redirect 301 /.well-known/caldav /remote.php/dav

<IfModule mod_security2.c>
  SecRuleEngine Off
</IfModule>

<IfModule mod_rewrite.c>
	RewriteEngine on
	RewriteCond %{SERVER_NAME} =%{SERVER_NAME}
	RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</IfModule>

</Directory>

<FilesMatch \\.php$>
  SetHandler "proxy:unix:/var/run/php/php7.3-fpm.nextcloud.sock|fcgi://localhost"
</FilesMatch>

<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=15552000; inextcloudludeSubDomains"
  Header always set Referrer-Policy "no-referrer"
</IfModule>

</VirtualHost>
EOF
# enable $ddns4 site
a2ensite $ddns4_nc.conf


#####################
# pihole admin Site #
#####################

cat <<EOF > /etc/apache2/sites-available/pi-admin.conf
<Location /admin>
  Authtype Basic
  Authname "Password Required"
  AuthUserFile /etc/apache2/.htpasswd
  #Require valid-user
  Require user $appw
  Require ip $local_net.
  Require forward-dns $ddns1
</Location>

<IfModule security2_module>
	SecRuleEngine On
</IfModule>

<IfModule mod_rewrite.c>
	RewriteEngine on
	RewriteCond %{SERVER_NAME} =%{SERVER_NAME}
	RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</IfModule>
 
Header unset X-Powered-By
Header always set Content-Security-Policy "default-src https: data: 'self' 'unsafe-inline' 'unsafe-eval'; form-action https: 'self'; referrer origin;"
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options sameorigin
Header always set X-XSS-Protection "1; mode=block"

EOF
# enable pihole admin Site
a2ensite pi-admin.conf


##############################################
# apache2 proxy config site (Shell in a Box) #
##############################################

cat <<EOF > /etc/apache2/sites-available/shellinabox.conf
ProxyRequests Off
 
<Proxy *>
  AddDefaultCharset off
  Require all granted
</Proxy>
 
<Location /shell>
  ProxyPass http://localhost:8700/
  Authtype Basic
  Authname "Password Required"
  AuthUserFile /etc/apache2/.htpasswd
  Require user $appw
  Require ip $local_net.
  Require forward-dns $ddns1
</Location>

<IfModule security2_module>
	SecRuleEngine Off
</IfModule>

<IfModule mod_rewrite.c>
	RewriteEngine on
	RewriteCond %{SERVER_NAME} =%{SERVER_NAME}
	RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</IfModule>

# Redirect permanent /shell https://$ddns1/shell
EOF
# enable apache proxy site (Shell in a Box)
a2ensite shellinabox.conf


##################
# Webalizer Site #
##################

cat <<EOF > /etc/apache2/sites-available/apache_webalizer.conf
<VirtualHost *:80>
  ServerName $ddns5
  ServerAdmin webmaster@localhost
  
  LogLevel warn
  ErrorLog \${APACHE_LOG_DIR}/error_$ddns5.log
  CustomLog \${APACHE_LOG_DIR}/access_$ddns5.log combined

  DocumentRoot /var/www/webalizer

<Directory /var/www/webalizer>
  Options +Indexes
  Authtype Basic
  Authname "Password Required"
  AuthUserFile /etc/apache2/.htpasswd
  #Require valid-user
  Require user $appw
  Require ip $local_net.
  Require forward-dns $ddns5
</Directory>

<IfModule security2_module>
	SecRuleEngine On
</IfModule>

<IfModule mod_rewrite.c>
	RewriteEngine on
	RewriteCond %{SERVER_NAME} =%{SERVER_NAME}
	RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</IfModule>

</VirtualHost>

Header unset X-Powered-By
Header always set Content-Security-Policy "default-src https: data: 'self' 'unsafe-inline' 'unsafe-eval'; form-action https: 'self'; referrer origin;"
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options sameorigin
Header always set X-XSS-Protection "1; mode=block"

EOF
# enable Webalizer Site
a2ensite apache_webalizer.conf

# Webalizer Config
mkdir /var/www/webalizer/$ddns1
mkdir /var/www/webalizer/$ddns2
mkdir /var/www/webalizer/$ddns3
mkdir /var/www/webalizer/$ddns4
mkdir /var/www/webalizer/$ddns5
mkdir /var/www/webalizer/standard
chown -R www-data:www-data /var/www/webalizer
chmod 750 /var/www/webalizer/

if [ -z "$skip" ]
	then
cp -r /mnt/nas/etc/webalizer/* /etc/webalizer/
	exit 
fi

chown www-data:www-data /var/log/apache2/*


###################
# Apache security #
###################

echo "nameserver 159.69.114.157" > /etc/resolv.conf
# modsecurity config
git clone https://github.com/coreruleset/coreruleset /etc/apache2/owasp-modsecurity-crs
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf 
sed -i "s/SecRuleEngine.*/SecRuleEngine On/g" /etc/modsecurity/modsecurity.conf
mv /etc/apache2/owasp-modsecurity-crs/crs-setup.conf.example \ 
	/etc/apache2/owasp-modsecurity-crs/crs-setup.conf
mv /etc/apache2/owasp-modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example \ 
	/etc/apache2/owasp-modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
mv /etc/apache2/owasp-modsecurity-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example \
	/etc/apache2/owasp-modsecurity-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf

# Apache security2 modul config
cat <<EOF >> /etc/apache2/apache2.conf
<IfModule security2_module>
     SecRuleEngine On
     IncludeOptional /etc/apache2/owasp-modsecurity-crs/crs-setup.conf
     IncludeOptional /etc/apache2/owasp-modsecurity-crs/rules/*.conf
     ServerTokens OS
     SecServerSignature "Apache/2.2.16 (Unix)"
 </IfModule>
ServerName 127.0.0.1
EOF
# test it see apache error log
# https://your_site.com/?param="><script>alert(1);</script>


################
# Apache modul #
################

a2enmod headers security2 proxy_fcgi

# apache2 mod needed for shell in a box
a2enmod proxy_balancer proxy proxy_http


#######################
# Apache test scripts #
#######################

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
foreach \$key (sort keys(%ENV)) {
      print "\$key = \$ENV{\$key}<BR>\n";
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


#################
# dyndns update #
#################

if [ -z "$skip" ]
	then
cat <<EOF > /etc/default/ddclient
run_dhclient="false"
run_ipup="false"
run_daemon="true"
daemon_interval="300"
EOF

cat <<EOF > /etc/ddclient.conf
# Configuration file for ddclient generated by debconf
# /etc/ddclient.conf
 
protocol=dyndns2
use=web, if=eth0
ssl=yes
 
# domain 1
server=$ddns_srv
login=$ddns2
password='yjgt-rqgi-aboc'
$ddns2
 
#domain 2
server=$ddns_srv
login=$ddns3
password='tknm-socz-ehtk'
$ddns3
 
#domain 3
server=$ddns_srv
login=$ddns4
password='tqzl-qggo-nzcu'
$ddns4

#domain 4
server=$ddns_srv
login=$ddns5
password='plyc-plsb-bzwb'
$ddns5
EOF

echo "nameserver 159.69.114.157" > /etc/resolv.conf
apt install ddclient -y
# sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install ddclient
# mv /etc/default/ddclient /etc/default/ddclient_org
# dpkg-reconfigure ddclient

systemctl daemon-reload
systemctl restart ddclient
systemctl enable ddclient
	exit
fi

##########################
# Apache letsencrypt SSL #
##########################

mkdir /var/www/html/pic
mkdir /var/www/nextcloud

cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf_org
apt install python3-certbot-apache -y
certbot --noninteractive --agree-tos  --no-redirect -m $ssl_email -d $ddns1,$ddns2,$ddns4,$ddns3,$ddns5 --apache


#####################
# Install WireGuard #
#####################

mkdir -p /etc/pivpn/wireguard/setupVars.conf 
cat <<EOF >> /etc/pivpn/wireguard/setupVars.conf 
PLAT=Raspbian
OSCN=buster
USING_UFW=0
IPv4dev=eth0
IPv4addr=$local_net.29/24
IPv4gw=$local_net.254
install_user=$suname
install_home=/home/$suname
VPN=wireguard
pivpnPORT=51820
pivpnDNS1=10.6.0.1
pivpnDNS2=
pivpnHOST=$ddns1
INPUT_CHAIN_EDITED=0
FORWARD_CHAIN_EDITED=1
pivpnPROTO=udp
pivpnMTU=1420
pivpnDEV=wg0
pivpnNET=10.6.0.0
subnetClass=24
ALLOWED_IPS="0.0.0.0/0, ::0/0"
UNATTUPG=1
EOF

echo "nameserver 159.69.114.157" > /etc/resolv.conf
# debconf-get-selections | grep iptables-persistent
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
apt install openvpn iptables-persistent grepcidr expect wireguard-tools qrencode unattended-upgrades -y

curl -L https://raw.githubusercontent.com/pivpn/pivpn/master/auto_install/install.sh | bash


############### 
# jail chroot #
###############

echo "nameserver 159.69.114.157" > /etc/resolv.conf
apt install build-essential autoconf automake libtool flex bison debhelper binutils -y
wget -O /root/jailkit-2.22.tar.gz https://olivier.sessink.nl/jailkit/jailkit-2.22.tar.gz
cd /root/
tar xvfz jailkit-2.22.tar.gz
cd jailkit-2.22
echo 5 > debian/compat
./debian/rules binary
cd ..
dpkg -i jailkit_2.22*.deb
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
useradd -m $jail_user
echo -e "$jail_pw\n$jail_pw" | passwd $jail_user
/usr/sbin/jk_jailuser -j /home/jail -s /usr/sbin/jk_lsh -m $jail_user
/usr/sbin/jk_jailuser -m -j /home/jail $jail_user
#sed -i 's/$jail_user/#$jail_user/g' /home/jail/etc/passwd
echo "root:x:0:0:root:/root:/bin/bash" > /home/jail/etc/passwd
echo "$jail_user:x:1002:1002:,,,:/home/$jail_user:/bin/bash" >> /home/jail/etc/passwd
rm -rf /home/jail/etc/jailkit/ 
cd /home/$suname


##############
#  influxdb  #
##############

# with kali = apt install influxdb-client influxdb
# curl -sL https://repos.influxdata.com/influxdb.key | sudo apt-key add -
# echo "deb https://repos.influxdata.com/debian buster stable" | sudo tee /etc/apt/sources.list.d/influxdb.list
# influx backup Syntax
# influxd backup -portable -db influxdb /mnt/nas/---install---/fritz_influxdb/

echo "nameserver 159.69.114.157" > /etc/resolv.conf
apt install influxdb -y
service influxdb start
/bin/systemctl daemon-reload
/bin/systemctl enable influxdb

If ! [ -z "$skip" ]
	then
influx -execute 'CREATE DATABASE influxdb'
	exit
fi

if [ -z "$skip" ]
	then
influxd restore -portable -db influxdb /mnt/nas/---install---/fritz_influxdb/
	exit
fi

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

echo "nameserver 159.69.114.157" > /etc/resolv.conf
# echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
# wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -

apt install grafana -y

if [ -z "$skip" ]
	then
cp /mnt/nas/---install---/grafana.db /var/lib/grafana/
grafana-cli admin reset-admin-password admin
	exit
fi

service grafana-server start
/bin/systemctl daemon-reload
/bin/systemctl enable grafana-server
update-rc.d grafana-server defaults


###################
# fail2ban config #
###################
# fail2ban-regex /var/www/nextcloud/data/nextcloud.log /etc/fail2ban/filter.d/nextcloud.conf

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

# If you don't install squid
mkdir /var/log/squid
touch /var/log/squid/access.log

# if you don't install nextcloud
mkdir -p /var/www/nextcloud/data/
touch /var/www/nextcloud/data/nextcloud.log


##################
# samba unattend #
##################

echo "nameserver 159.69.114.157" > /etc/resolv.conf
echo "samba-common samba-common/workgroup string  WORKGROUP" | sudo debconf-set-selections
echo "samba-common samba-common/dhcp boolean true" | sudo debconf-set-selections
echo "samba-common samba-common/do_debconf boolean true" | sudo debconf-set-selections
apt install samba samba-common-bin smbclient -y


################
# config samba #
################

mkdir /mnt/samba

cp /etc/samba/smb.conf /etc/samba/smb.conf_org
cat <<EOF > /etc/samba/smb.conf
[pi4]
   comment = samba share
   path = /mnt/samba
   guest ok = no
   browseable = yes 
   create mask = 0600
   directory mask = 0700
   valid users = $suname

[root]
    comment = root
    path = /
    guest ok = no
    browseable = yes
    valid users = $suname
    read only = yes
EOF

# samba password
echo -e "$smb_pw\n$smb_pw" | smbpasswd -a $suname


######################
#   install unbound  #
######################

echo "nameserver 159.69.114.157" > /etc/resolv.conf
apt install unbound -y
wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
chown unbound:unbound /var/lib/unbound/root.hints

# update root.hints
wget -O /usr/local/bin/autoupdatelocalroot https://raw.githubusercontent.com/henosch/pi4/main/scripts/autoupdatelocalroot
chmod 755 /usr/local/bin/autoupdatelocalroot
echo -e "$(crontab -l)\n20 4 * * 0    /usr/local/bin/autoupdatelocalroot" | crontab -u $suname -
wget -O /usr/local/bin/updateunboundconf https://raw.githubusercontent.com/henosch/pi4/main/scripts/updateunboundconf
chmod 755 /usr/local/bin/updateunboundconf

cat <<EOF > /etc/unbound/unbound.conf.d/pi-hole.conf
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
WEBPASSWORD=$pi_hole_pw
DNSMASQ_LISTENING=local
PIHOLE_INTERFACE=eth0
IPV4_ADDRESS=$IPV4_ADDRESS/24
IPV6_ADDRESS=$IPV6_ADDRESS
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
https://raw.githubusercontent.com/henosch/my-pihole-lists/master/blacklist.txt
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

echo "nameserver 159.69.114.157" > /etc/resolv.conf
# pihole without inside http server. We use apache 2
curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended --disable-install-webserver
usermod -a -G pihole www-data

chown pihole:pihole -R /etc/pihole/ 
echo -e "$(crontab -l)\n30 2 * * 6    /etc/pihole/update_myblocklist.sh" | crontab -u root -
echo -e "$(crontab -l)\n30 2 * * 7 pihole   /usr/local/bin/pihole updatePihole" | crontab -u root -

echo "nameserver 159.69.114.157" > /etc/resolv.conf

# useful commands
# sqlite3 /etc/pihole/gravity.db "SELECT domain FROM vw_blacklist;"
# sqlite3 /etc/pihole/gravity.db "SELECT domain FROM vw_whitelist;"
# sqlite3 /etc/pihole/gravity.db "SELECT domain FROM vw_regex_blacklist;"
# sqlite3 /etc/pihole/gravity.db "SELECT domain FROM vw_regex_whitelist;"
# sqlite3 /etc/pihole/gravity.db "SELECT address FROM adlist;"
# sqlite3 /etc/pihole/gravity.db ".schema domainlist"
# sqlite3 /etc/pihole/gravity.db ".schema"

# statistic
wget -O /etc/pihole/uniq_urls.sh https://raw.githubusercontent.com/henosch/pi4/main/scripts/uniq_urls.sh 
chmod +x /etc/pihole/uniq_urls.sh


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

# enable shellinbox
# cat <<EOF >> /etc/rpimonitor/data.conf
# web.addons.1.title=ShelleInABox
# web.addons.1.addons=custom
# web.addons.1.showtitle=false
# web.addons.1.url=http://localhost:8700/
# web.addons.1.allowupdate=false
# EOF

cat <<EOF > /etc/cron.d/rpimonitor
# run at 03:05 to update local repository database
05 03 * * * root /usr/bin/apt-get update > /dev/null 2>&1
 
# run at 03:10 to update status
10 03 * * * root /usr/share/rpimonitor/scripts/updatePackagesStatus.pl
EOF

cat <<EOF > /etc/cron.d/top3
* * * * * root cd /usr/share/rpimonitor/web/addons/top3; ./top3 > top3.html
EOF

/etc/init.d/rpimonitor update
/etc/init.d/rpimonitor install_auto_package_status_update


##################
# install webmin #
##################
echo "nameserver 159.69.114.157" > /etc/resolv.conf

apt install libauthen-pam-perl apt-show-versions libio-pty-perl -y
wget -O /root/webmin_1.974_all.deb http://prdownloads.sourceforge.net/webadmin/webmin_1.974_all.deb
dpkg --install /root/webmin_1.974_all.deb


###############
# shellinabox #
###############

# shellinabox config file
sudo -i
cp /etc/default/shellinabox /etc/default/shellinabox_org
cat <<EOF > /etc/default/shellinabox
SHELLINABOX_DAEMON_START=1
SHELLINABOX_PORT=8700
SHELLINABOX_ARGS="--no-beep --localhost-only --disable-ssl -s /:LOGIN"
EOF
#ssh -g -R remote_port:localhost:local_port root@remote.server

# terminal white on black
mv /etc/shellinabox/options-enabled/00+Black\ on\ White.css /etc/shellinabox/options-enabled/00_Black\ on\ White.css \
 && mv /etc/shellinabox/options-enabled/00_White\ On\ Black.css /etc/shellinabox/options-enabled/00+White\ On\ Black.css

echo "nameserver 159.69.114.157" > /etc/resolv.conf

# Newer kernel available
# needrestart -k
# remove needrestart, because kernel message pop up every time

if dpkg-query -W -f='${Status}' needrestart | grep "ok installed"; then apt remove needrestart -y; fi


#####################
# Install nextcloud #
#####################

useradd -M -s /bin/false nextcloud
cat <<EOF >/etc/php/7.3/fpm/pool.d/nextcloud.conf
[nextcloud]
user = nextcloud
group = nextcloud

listen = /var/run/php/php7.3-fpm.nextcloud.sock

listen.owner = www-data
listen.group = www-data

php_admin_value[open_basedir] = /var/www/nextcloud/:/tmp/:/dev/

env[HOSTNAME] = $HOSTNAME
env[PATH] = /usr/local/bin:/usr/bin:/bin
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp

security.limit_extensions =
php_admin_value[cgi.fix_pathinfo] = 1

pm = dynamic
pm.max_children = 5
pm.start_servers = 3
pm.min_spare_servers = 2
pm.max_spare_servers = 4
pm.max_requests = 200
EOF

#PHP Mod fpm/php.ini
cp /etc/php/7.3/fpm/php.ini /etc/php/7.3/fpm/php.ini_org
sed -i "s/memory_limit = 128M/memory_limit = 512M/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.enable=.*/opcache.enable=1/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.enable_cli=.*/opcache.enable_cli=1/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=8/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=10000/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.memory_consumption=.*/opcache.memory_consumption=128/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.save_comments=.*/opcache.save_comments=1/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.revalidate_freq=.*/opcache.revalidate_freq=1/" /etc/php/7.3/fpm/php.ini


##################
# fritzbox tools #
##################

echo "nameserver 159.69.114.157" > /etc/resolv.conf
wget -O /root/fb-tools.deb 'http://www.mengelke.de'`wget -q -O- http://www.mengelke.de/Projekte/FritzBoxTools.html \
| grep -a -o -E '/Download;fb-tools.deb\\?[a-f0-9]+'`
# dpkg -i /mnt/nas/---deb---/fb-tools.deb 
dpkg -i /root/fb-tools.deb
usermod -a -G staff $suname
fb_tools info update
fb_tools plugin install update

mv /usr/local/share/fb_tools/fb_config.php /usr/local/share/fb_tools/fb_config.php_org
# cp /mnt/nas/---install---/fb_config.php /usr/local/share/fb_tools/

# fb_tools fritz.box logintest
# fb_tools my logintest
# fb_tools fritz.box boxinfo
# fb_tools my anrufliste
# fb_tools systemstatus
# fb_tools fritz.box getip
# fb_tools fritz.box getip filter:ipv4

# internet reconnect
# fb_tools reconnect

# fb_tools my wh 017615151515 FON1
# fb_tools my ereignisse
# fb_tools my unprotect yes

# checksum from file
# fb_tools konfig file-calcsum my_decrypt_export

# fb_tools konfig file-decrypt FRITZ.Box\ 7582\ 156.07.12i_04.12.20_2306.export 2577831q
# fb_tools my konfig export my_export
# fb_tools my konfig import-calcsum my_export
# fb_tools my konfig export-decrypt my_decrypt_export
# fb_tools my konfig export my_export_pass pass:Test12345
# fb_tools my websync AVM https://download.avm.de/fritzbox/fritzbox-7582 -gm -d


###############
# ssh key $gb #
###############

if [ -z "$skip" ]
	then
echo "nameserver 159.69.114.157" > /etc/resolv.conf
apt install keychain libpam-ssh-agent-auth
cp -R /mnt/nas/home/$suname/scripts/ .
cp /mnt/nas/---install---/config .ssh/
cp /mnt/nas/home/$suname/$gb.id_rsa* /home/$suname/.ssh/
chown -R $suname:$suname /home/$suname/
chmod 700 /home/$suname/.ssh
chmod 600 /home/$suname/.ssh/$gb.id_rsa*
echo "Defaults env_keep += SSH_AUTH_SOCK" | tee /etc/sudoers.d/00_SSH_AUTH_OK
chmod 0440 /etc/sudoers.d/00_SSH_AUTH_OK

cp /etc/pam.d/sudo /root/pam.d_sudo_backup
cat <<EOF > /etc/pam.d/sudo
#%PAM-1.0
 
auth [success=2 default=ignore] pam_ssh_agent_auth.so file=/etc/ssh/sudo_known_hosts
@include common-auth
@include common-account
@include common-session-noninteractive
 
session required pam_permit.so
session required pam_limits.so
EOF

sudo -u $suname echo -e "$(crontab -l)\n00 00 * * *    bash    ~/scripts/web_$gb/copy.sh >>/var/log/web_log 2>&1" | crontab -u $suname -
sudo -u $suname echo -e "$(crontab -l)\n59 23 30 * *   bash    ~/scripts/web_$gb/logrotate.sh >>/var/log/web_log 2>&1" | crontab -u $suname -
touch /var/log/web_log
chown $suname:$suname /var/log/web_log
	exit
fi


##################
# install docker #
##################

echo "nameserver 159.69.114.157" > /etc/resolv.conf
apt install docker.io -y

cat <<EOF >>/etc/docker/daemon.json
{
   "dns": ["172.0.0.1", "80.241.218.68"]
}
EOF

if [ -z "$skip" ]
	then
sudo -u $suname cp -R /mnt/nas/home/$suname/swgoh_tracker /home/$suname/
cd /home/$suname/swgoh_tracker
sudo -u $suname sh update_all_docker.sh 24
	exit
fi


#############################
# mysql_secure_installation #
#############################

systemctl start mysql

mysql -u root -p$root_pw -e "SET PASSWORD FOR root@localhost = PASSWORD('$root_pw');FLUSH PRIVILEGES;"
mysql -u root -p$root_pw -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '$root_pw';FLUSH PRIVILEGES;"
mysql -u root -p$root_pw -e "DELETE FROM mysql.user WHERE User='';"
mysql -u root -p$root_pw -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
# mysql -u root -p$root_pw -e "DROP DATABASE test;DELETE FROM mysql.db WHERE DB='test' OR DB='test_%';"

mysql -u root -p$root_pw -e "CREATE DATABASE $database;"
mysql -u root -p$root_pw -e "CREATE USER '$sql_user'@'localhost' IDENTIFIED BY '$sql_user_pw'";
mysql -u root -p$root_pw -e "GRANT ALL PRIVILEGES ON $database.* TO '$sql_user'@'localhost' IDENTIFIED BY '$sql_user_pw';FLUSH PRIVILEGES;"
mysql -u root -p$root_pw -e "GRANT ALL PRIVILEGES ON $database.* TO '$sql_user'@'%' IDENTIFIED BY '$sql_user_pw';FLUSH PRIVILEGES;"
mysql -u root -p$root_pw -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '$root_pw';FLUSH PRIVILEGES;"

# remote access mysql
if [ -z "$skip" ]
	then
sed -i 's/127.0.0.1/$IPV4_ADDRESS/g' /etc/mysql/mariadb.conf.d/50-server.cnf
	exit
fi


###############
# custom motd #
###############

if [ -z "$skip" ]
	then
cp /mnt/nas/etc/update-motd.d/10-uname /etc/update-motd.d/10-uname
rm /etc/motd
	exit
fi

# mv /usr/bin/vim.tiny /usr/bin/vim.tiny_org
# ln -s /usr/bin/vi /usr/bin/vim.tiny

###########################
# special rights for work #
###########################
sudo -i

############
# fritzctl #
############

# dpkg -i /mnt/nas/---deb---/fritzctl_1.4.23_armhf.deb
wget -O /root/fritzctl_1.4.23_armhf.deb https://github.com/henosch/pi4/raw/main/apk/fritzctl_1.4.23_armhf.deb
dpkg -i  /root/fritzctl_1.4.23_armhf.deb


# fritzctl configure
cp /etc/fritzctl/fritzctl.json /etc/fritzctl/fritzctl.json_org
cat <<EOF > /etc/fritzctl/fritzctl.json
{
   "protocol": "https",
   "host": "fritz.box",
   "port": "",
   "loginURL": "/login_sid.lua",
   "username": "",
   "password": "$fritz_pw",
   "skipTlsVerify": false,
   "certificateFile": "/etc/fritzctl/fritz.pem"
 }
EOF

fritzctl certificate export > /etc/fritzctl/fritz.pem
# fritzctl list landevices
# fritzctl list logs


##################
# fritzbox tools #
##################

cat <<EOF > /usr/local/share/fb_tools/fb_config.php
<?php if(!defined('fb_tools')) die("Preset-File for fb_tools"); // (charset=ascii / tabs=8 / lines=cr+lf / lang=de)
\$cfg['preset'] = array(
     'my' => array('sock' => 'https', 'host' => 'fritz.box', 'port' => 443, 'user' => '', 'pass' => '$fritz_pw'),
);
?>
EOF


###################################################
# PW is in 1pw Raspberry PI 4 Apache/.htaccess PW #
###################################################

cat <<EOF >> /etc/apache2/.htpasswd
$appw:\$2y\$05\$3/FaWHXG2J.kc0BKDzoDcOEoiDDniH3NArwvpTWQS2isG9IjoGyL6
EOF
chmod 640 /etc/apache2/.htpasswd

echo "NTP=213.136.94.10 80.241.218.68 78.46.223.134" >> /etc/systemd/timesyncd.conf


####################
# crontab for root #
####################

echo -e "$(crontab -l)\n0 0 * * *    webalizer -c /etc/webalizer/webalizer.conf" | crontab -u root -
echo -e "$(crontab -l)\n0 0 * * *    webalizer -c /etc/webalizer/access_$ddns1.conf" | crontab -u root -
echo -e "$(crontab -l)\n0 0 * * *    webalizer -c /etc/webalizer/access_$ddns2_rpi.conf" | crontab -u root -
echo -e "$(crontab -l)\n0 0 * * *    webalizer -c /etc/webalizer/access_$ddns3_pic.conf" | crontab -u root -
echo -e "$(crontab -l)\n0 0 * * *    webalizer -c /etc/webalizer/access_$ddns4_nextcloud.conf" | crontab -u root -
echo -e "$(crontab -l)\n0 0 * * *    webalizer -c /etc/webalizer/access_$ddns5.conf" | crontab -u root -
echo -e "$(crontab -l)\n0 1 2 * *    /usr/bin/certbot renew >>/var/log/letsencrypt/letsencrypt.log && service apache2 reload" | crontab -u root -

if [ -z "$skip" ]
	then
echo -e "$(crontab -l)\n0 7 * * 1    influxd backup -portable -db influxdb /mnt/nas/---install---/fritz_influxdb/" | crontab -u root -
echo -e "$(crontab -l)\n0 7 * * 2    sqlite3 /etc/pihole/pihole-FTL.db '.backup /mnt/nas/---install---/pihole-FTL.db.backup'" | crontab -u root -
	exit
fi

	
#################
# fritzcollectd #
#################

echo "nameserver 159.69.114.157" > /etc/resolv.conf
yes | pip install fritzcollectd
cp /etc/collectd/collectd.conf /etc/collectd/collectd.conf_org
cat <<EOF >> /etc/collectd/collectd.conf
<Plugin python>
     Import "fritzcollectd"
 
     <Module fritzcollectd>
         Address "fritz.box"
         Port 49000
         User "collectd"
         Password "$fritz_coll"
         Hostname "FritzBox"
         Instanextcloude "1"
         Verbose "False"
     </Module>
</Plugin>

<Plugin network>
    Server "127.0.0.1" "25826"
</Plugin>
EOF

sed -i 's/#LoadPlugin python/LoadPlugin python/g' /etc/collectd/collectd.conf
sed -i 's/#LoadPlugin network/LoadPlugin network/g' /etc/collectd/collectd.conf

echo "NTP=213.136.94.10 80.241.218.68 78.46.223.134" >> /etc/systemd/timesyncd.conf

if dpkg-query -W -f='${Status}' modsecurity-crs | grep "ok installed"; then apt remove modsecurity-crs -y; fi


# backup pihole with rclone
echo "nameserver 159.69.114.157" > /etc/resolv.conf
curl https://rclone.org/install.sh | sudo bash
curl https://raw.githubusercontent.com/henosch/rclone-backup/master/install.sh | sudo bash
