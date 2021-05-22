#!/bin/bash
# Only for testing

[ "$UID" -eq 0 ] || exec sudo "$0" "$@"

# local vars testing
mkdir ~/testing/ && chmod 700 ~/testing/
cat <<EOF > ~/testing/testme
$SUSER
EOF
echo $USER
echo $SUSER
chmod 600 ~/testing/testme


touch root.txt 
sudo -u mike touch mike.txt
mkdir Heft 
