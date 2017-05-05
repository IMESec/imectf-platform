if [ "$USER" != 'root' ]; then
  echo "ERROR: Script must be run using root!"
  exit
fi

mkdir -p /problems
chmod 751 /problems

useradd -s /bin/bash oracle
