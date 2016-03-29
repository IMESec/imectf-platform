tinyctf-platform
================

`tinyctf-platform` is yet another open-source (jeopardy style) CTF platform. It is relatively easy to set up and modify. Hopefully it will become even better over time, with other people contributing.

![alt text](https://i.imgur.com/ofB52E4.png "tinyctf-platform in action")

Deployment
----------

To deploy `tinyctf-platform` on an EC2 instance, execute the following commands:

Become root, upgrade

    sudo su
    yum upgrade -y
    
Install some prerequisites

    yum install -y git
    yum install -y gcc-c++
    yum install -y python-devel
    yum install -y sqlite3
    
Install Flask and dataset

    easy_install Flask
    easy_install dataset
    easy_install dateparser
    easy_install bleach
    exit
    
Install python-dateutil version 1.5:

    pip install python-dateutil==1.5
    
Clone the repo

    git clone https://github.com/balidani/tinyctf-platform.git
    cd tinyctf-platform/
    
Build the database

    ./buildTables.sh
    
Start the server

    python server.py

*Note*: Flask should run on top of a proper web server if you plan to have many players.

Caveats
-------

* CSRF is currently not addressed

Upgrades
-------

* This fork stores old competitions so it can run continously.
