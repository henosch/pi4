#!/bin/bash
# Only for testing

[ "$UID" -eq 0 ] || exec sudo bash "$0" "$@"

# local vars testing
mkdir ~/testing/ && chmod 700 ~/testing/
cat <<EOF > ~/testing/testme
$SUSER
EOF
chmod 600 ~/testing/testme
