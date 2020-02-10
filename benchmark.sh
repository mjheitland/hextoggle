#!/usr/bin/env bash

if [ $# -lt 1 ]; then
  echo 1>&2 "Usage: $0 path/to/hextoggle"
  exit 2
elif [ $# -gt 1 ]; then
  echo 1>&2 "$0: too many arguments"
  exit 2
fi

dd if=/dev/random of=.temp_hextoggle_bin bs=1048576 count=64
echo -e '\n\nConvert binary -> hex:'
time $1 .temp_hextoggle_bin .temp_hextoggle_hex
echo -e '\n\nConvert hex -> binary:'
time $1 .temp_hextoggle_hex .temp_hextoggle_bin
rm .temp_hextoggle_bin .temp_hextoggle_hex

