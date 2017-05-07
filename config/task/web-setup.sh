#!/bin/bash

if [[ $# -ne 2 ]] ; then
  echo "usage: bash web-setup.sh <script> <port>"
  exit
fi

if [[ ! -f "$1" ]] ; then
  echo "file $1 does not exists"
  exit
fi

if ! ([[ "$2" =~ ^[0-9]+$ ]] && [[ "$2" -ge 1024 ]] && [[ "$2" -le 65535 ]]) ; then
  echo "port out of range (1024 to 65535)"
  exit
fi

port="$2"
user=cracked_"$2"

# create user for task
useradd -m -s /bin/bash "$user"

# create problem directory
# TODO use salt from envvar
dir=/problems/$(echo -n "$1$2" | md5sum | cut -d ' ' -f 1)

mkdir -p $dir
chown oracle $dir
chgrp $user $dir
chmod 771 $dir
echo "Created directory: $dir"

cp -r * $dir
echo "Copied files"

bin=$dir/"$1"

# change bin owner
chown oracle $dir/*
chgrp $user $dir/*
chmod 775 $dir/*
echo "Changed script permissions"

# create service
serv=/etc/systemd/system/$user.service
(echo  "[Unit]" \
; echo "Description=Web task $port" \
; echo "After=network.target" \
; echo \
; echo "[Service]" \
; echo "User=$user" \
; echo "WorkingDirectory=$dir" \
; echo "ExecStart=$bin" \
; echo "Restart=always" \
; echo "RestartSec=0" \
; echo \
; echo "[Install]" \
; echo "WantedBy=multi-user.target") > $serv

systemctl stop $user
systemctl daemon-reload
systemctl start $user
systemctl enable $user

echo "Created service"
