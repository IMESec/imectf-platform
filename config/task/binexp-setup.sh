#!/bin/bash

if [[ $# -ne 2 ]] ; then
  echo "usage: bash binexp-setup.sh <binary> <port>"
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
chmod 1750 $dir
echo "Create directory: $dir"

# configure bin owner
cp "$1" $dir
bin=$dir/"$1"
chown oracle $bin
chgrp $user $bin
chmod 2750 $bin
echo "Configured binary"

# change flag owner if exists
if [[ -f "flag.txt" ]]; then
  echo "Found flag.txt!"
  f=$dir/flag.txt
  cp flag.txt $f
  chown oracle $f
  chgrp $user $f
  chmod 440 $f
  echo "Configured flag permissions"
fi

# FIXME exec: Exec format error
# create run.sh
run=$dir/run.sh
(echo  "#!/bin/bash" \
; echo "exec timeout -s9 5m $bin") > $run
chown oracle $run
chgrp $user $run
chmod 2750 $run

# create service
serv=/etc/systemd/system/$user.service
(echo  "[Unit]" \
; echo "Description=BinExp task $port" \
; echo "After=network.target" \
; echo \
; echo "[Service]" \
; echo "User=$user" \
; echo "WorkingDirectory=$dir" \
; echo "ExecStart=/usr/bin/ncat -lvkp $port -e $run" \
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
