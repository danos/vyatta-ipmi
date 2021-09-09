#!/bin/bash

# Copyright (c) 2021, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
daemon="${1}"

cat <<EOF > src/ipmitool
#!/bin/bash
echo "Running "\$0" "\$@" >&2
exit 0
EOF
chmod a+x src/ipmitool

PATH=$(pwd)/src:$PATH

"$daemon" --interval 5 --timeout 2 &
pid=$!

sleep 2
kill -15 %1
wait $!

rm -f src/ipmitool

exit $?
