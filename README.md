## How to write a feature app for network_monitor?
!!! WILL BE UPDATED SOON !!!

## Steps to run project locally
1. install postgresql
    - $ sudo apt-get install postgresql postgresql-contrib postgresql-server-dev-all -y
1. prepare database config
    1. $ sudo su - postgres
    1. $ psql
    1. run this queries in psql:
        - CREATE DATABASE network_monitor;
        - GRANT ALL PRIVILEGES ON DATABASE network_monitor to postgres;
        - ALTER USER postgres WITH PASSWORD 'a';
    1. $ sudo vi /etc/postgresql/9.x/main/pg_hba.conf
    1. replace this line:

        local   all             postgres                                peer

        by:

        local   all             postgres                                md5
    1. $ sudo service postgresql restart
1. $ git clone https://github.com/Heteroskedastic/django-network-monitor.git
1. $ cd django-network-monitor
1. $ virtualenv -p python3 env
1. $ source env/bin/activate
1. $ pip install -r requirements.txt
1. $ cd network_monitor
1. $ python manage.py migrate --settings=network_monitor.settings.local
1. $ python manage.py runserver --settings=network_monitor.settings.local

## Installation steps on production
### Linux Installation(Ubuntu)
1. create an sudoer user on ubuntu called "appuser"
    - $ sudo adduser appuser
    - $ sudo adduser appuser sudo
1. login with appuser
1. install postgresql
    - $ sudo apt-get install postgresql postgresql-contrib postgresql-server-dev-all -y

1. prepare database config
    1. $ sudo su - postgres
    1. $ psql
    1. run this queries in psql:
        - CREATE DATABASE network_monitor;
        - GRANT ALL PRIVILEGES ON DATABASE network_monitor to postgres;
        - ALTER USER postgres WITH PASSWORD 'a';
    1. $ sudo vi /etc/postgresql/9.x/main/pg_hba.conf

    1. replace this line:

        local   all             postgres                                peer

        by:

        local   all             postgres                                md5
    1. $ sudo service postgresql restart

1. run installation script
    1. copy PROJECT_PATH/utils/install.sh to install.sh from repository
    1. $ chmod +x install.sh
    1. $ ./install.sh

1. configuration
    1. change server name in the following config file to server DNS(or ip):
        /etc/nginx/sites-enabled/network_monitor.conf
    1. change HOSTNAME in the custom project config file to server DNS(or ip):
        /opt/webapps/network_monitor/etc/custom_config.py
    1. update commented configs in /opt/webapps/network_monitor/etc/custom_config.py:
        - SECRET_KEY
        - MAILGUN_SERVER_NAME
        - MAILGUN_ACCESS_KEY
        - TWILIO_ACCOUNT_SID
        - TWILIO_AUTH_TOKEN
        - TWILIO_DEFAULT_CALLERID
        - SOCIAL_AUTH_GOOGLE_OAUTH2_KEY
        - SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET
        - ...

1. restart the services
    1. $ sudo service supervisor restart
    1. $ sudo service nginx restart
