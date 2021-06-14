#!/bin/bash
# Only for testing

[ "$UID" -eq 0 ] || exec sudo "$0" "$@"

if exist ~/testing/testme then rm -r ~/testing/
# local vars testing
mkdir ~/testing/ && chmod 700 ~/testing/
cat <<EOF > ~/testing/testme
#!/bin/bash
user1=trump
user2=biden
EOF
sh ~/testing/testme
echo $user1
echo $user2
