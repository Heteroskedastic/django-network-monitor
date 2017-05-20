#!/bin/bash

BRANCH=master
if [ -n "$1" ]; then
    BRANCH=$1
fi

NAME="network_monitor"
GITURL=https://github.com/Heteroskedastic/django-network-monitor.git
ROOTDIR=/opt/webapps
PROJECTDIR=$ROOTDIR/$NAME
DJANGODIR=$PROJECTDIR/$NAME
ENVDIR=$PROJECTDIR/env
DJANGO_SETTINGS_MODULE=network_monitor.settings.main

echo "+++ Deploying $NAME: BRANCH=$BRANCH PROJECTDIR=$PROJECTDIR ..."

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
sudo supervisorctl stop $NAME
sudo supervisorctl stop $NAME-celery:*
sudo supervisorctl stop $NAME-mon_service
sleep 1
if [ ! -d "$ENVDIR" ]; then
    virtualenv -p python3 $ENVDIR
fi
source $ENVDIR/bin/activate
cd $DJANGODIR
pip install -r requirements.txt
pip install django-gunicorn
cd $DJANGODIR/network_monitor
python manage.py migrate --settings=$DJANGO_SETTINGS_MODULE --noinput
python manage.py collectstatic --settings=$DJANGO_SETTINGS_MODULE --noinput
sudo supervisorctl start $NAME
sudo supervisorctl start $NAME-celery:*
sudo supervisorctl start $NAME-mon_service
sudo service nginx restart

echo
echo "Finished!"
