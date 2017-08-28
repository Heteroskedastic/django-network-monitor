#!/bin/bash

BRANCH=master
if [ -n "$1" ]; then
    BRANCH=$1
fi

echo "+++ installing required libs ..."
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib postgresql-server-dev-all -y
sudo apt-get install nginx -y
sudo apt-get install python-dev -y
sudo apt-get install python3-dev -y
sudo apt-get install python-pip -y
sudo apt-get install redis-server -y
sudo apt-get install git -y
sudo apt-get install supervisor -y
sudo apt-get install libjpeg-dev zlib1g-dev -y
sudo apt-get install libxml2-dev libxslt-dev -y
sudo apt-get install nmap -y
sudo pip install virtualenv

# setup project
NAME="network_monitor"
GITURL=https://github.com/Heteroskedastic/django-network-monitor.git
ROOTDIR=/opt/webapps
PROJECTDIR=$ROOTDIR/$NAME
DJANGODIR=$PROJECTDIR/$NAME
ENVDIR=$PROJECTDIR/env
DJANGO_SETTINGS_MODULE=network_monitor.settings.main
USER=appuser                                      # the user to run as
GROUP=appuser                                     # the group to run as

echo "+++ creating project workspace in: $PROJECTDIR"
sudo mkdir -p $ROOTDIR
sudo chown $USER:$GROUP $ROOTDIR -R
mkdir -p $PROJECTDIR
mkdir -p $PROJECTDIR/run
mkdir -p $PROJECTDIR/logs
mkdir -p $PROJECTDIR/etc

if [ -d "$DJANGODIR" ]; then
    cd $DJANGODIR
    git reset --hard HEAD
    git pull origin
    git checkout $BRANCH
else
    git clone $GITURL -b $BRANCH $DJANGODIR
fi
cp $DJANGODIR/network_monitor/network_monitor/settings/external_config_sample.py $PROJECTDIR/etc/external_config.py

virtualenv -p python3 $ENVDIR
source $ENVDIR/bin/activate

sudo cp $DJANGODIR/utils/deploy.sh /usr/local/bin/"$NAME"_deploy
sudo chmod +x /usr/local/bin/"$NAME"_deploy
sudo cp $DJANGODIR/utils/backup.sh /usr/local/bin/"$NAME"_backup
sudo chmod +x /usr/local/bin/"$NAME"_backup
sudo cp $DJANGODIR/utils/supervisord.conf /etc/supervisor/conf.d/$NAME.conf
sudo cp $DJANGODIR/utils/nginx.conf /etc/nginx/sites-available/$NAME.conf
sudo ln -sf /etc/nginx/sites-available/$NAME.conf /etc/nginx/sites-enabled/$NAME.conf
cp $DJANGODIR/utils/gunicorn_start.sh $ENVDIR/bin/
chmod +x $ENVDIR/bin/gunicorn_start.sh
cp $DJANGODIR/utils/celery_start.sh $ENVDIR/bin/
chmod +x $ENVDIR/bin/celery_start.sh
cp $DJANGODIR/utils/mon_service_start.sh $ENVDIR/bin/
chmod +x $ENVDIR/bin/mon_service_start.sh

cd $DJANGODIR
pip install -r requirements.txt
pip install django-gunicorn
cd $DJANGODIR/network_monitor
python manage.py migrate --settings=$DJANGO_SETTINGS_MODULE --noinput
python manage.py collectstatic --settings=$DJANGO_SETTINGS_MODULE --noinput
sudo service supervisor restart
sudo supervisorctl restart $NAME
sudo supervisorctl restart $NAME-celery:*
sudo supervisorctl restart $NAME-mon_service
sudo service nginx restart

echo
echo "Finished!"
