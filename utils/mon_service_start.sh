#!/bin/bash

NAME="network_monitor"                                  # Name of the application
ROOTDIR=/opt/webapps
PROJECTDIR=$ROOTDIR/$NAME
DJANGODIR=$PROJECTDIR/$NAME
ENVDIR=$PROJECTDIR/env
SOCKFILE=$PROJECTDIR/run/$NAME-mon-service.sock
DJANGO_SETTINGS_MODULE=network_monitor.settings.main             # which settings file should Django use

echo "Starting $NAME-mon-service as `whoami`"

# Activate the virtual environment
source $ENVDIR/bin/activate
export DJANGO_SETTINGS_MODULE=$DJANGO_SETTINGS_MODULE
export PYTHONPATH=$DJANGODIR/network_monitor:$PYTHONPATH

# Create the run directory if it doesn't exist
RUNDIR=$(dirname $SOCKFILE)
test -d $RUNDIR || mkdir -p $RUNDIR

echo "$ENVDIR/bin/python manage.py mon_service --settings=${DJANGO_SETTINGS_MODULE}"
# Start your Django Unicorn
# Programs meant to be run under supervisor should not daemonize themselves (do not use --daemon)
exec $ENVDIR/bin/python $DJANGODIR/network_monitor/manage.py mon_service --settings=${DJANGO_SETTINGS_MODULE}
