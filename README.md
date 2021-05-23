# pi4 debian 10 installation 

+ ssh pi@192.168.11.29 # pw raspberry
+ sudo -i
+ passwd
+ passwd pi

+ adduser mike
+ adduser mike sudo
+ exit
+ exit
+ ssh mike@192.168.11.29
+ sudo -i

# install first 
curl https://raw.githubusercontent.com/henosch/pi4/main/01_install.sh | sudo bash

# install second 
curl https://raw.githubusercontent.com/henosch/pi4/main/02_install.sh | sudo bash
