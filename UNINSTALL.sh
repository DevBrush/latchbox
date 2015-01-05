#!/bin/sh

if [ $(id -u) != "0" ] ; then
  echo "This script must be run as root" 1>&2
    exit 1
fi
rm -f /usr/bin/latchbox
rm -f /usr/share/man/man1/latchbox.1.gz
echo "\033[1mLatchBox Uninstalled\033[0m"
