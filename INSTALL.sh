#!/bin/sh

version_lte() {
  [  "$1" = `echo -e "$1\n$2" | sort -V | head -n1` ]
}

if [ $(id -u) != "0" ] ; then
  echo "This script must be run as root" 1>&2
    exit 1
fi
if which go > /dev/null; then
  if version_lte `go version | awk '{ print $3 }' | cut -d'o' -f 2` 1.1.1; then
    echo "Go must be version 1.1.1 or higher"
    exit 1
  fi
else
  echo "Unmet Dependency: Go"
  exit 1
fi
mkdir -p /tmp/latchbox-install/src/github.com/PariahVi/latchbox/
cp -r * /tmp/latchbox-install/src/github.com/PariahVi/latchbox/
export GOPATH=/tmp/latchbox-install
echo "\033[1mBuilding latchbox...\033[0m\n"
go install github.com/PariahVi/latchbox
echo "\033[1mInstalling latchbox...\033[0m"
cp /tmp/latchbox-install/bin/latchbox /usr/bin/
echo "\033[1mInstalling Man Page\033[0m\n"
mkdir -p /usr/share/man/man1
cp /tmp/latchbox-install/src/github.com/PariahVi/latchbox/doc/latchbox.1.gz /usr/share/man/man1/
echo "\033[1mCleaning Up\033[0m\n"
rm -rf "/tmp/latchbox-install"
echo "\033[1mlatchbox Installed!\033[0m"
if ! [ `uname -s` = "Darwin" ]; then
  if which xclip > /dev/null; then
    echo "Optional dependencies for latchbox\n    xclip: provides clipboard functionality [installed]"
  else
    echo "Optional dependencies for latchbox\n    xclip: provides clipboard functionality"
  fi
fi
