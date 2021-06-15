#!/bin/bash
# Only for testing

[ "$UID" -eq 0 ] || exec sudo "$0" "$@"

rm -r ~/testing/
# local vars testing
mkdir ~/testing/ && chmod 700 ~/testing/
cat <<EOF > ~/testing/testme
user1=trump
user2=biden
EOF
. ~/testing/testme
echo $user1
echo $user2
