from .base import *
from . import base
base.CUSTOM_CONFIG_INI_PATH = os.path.join(BASE_DIR, 'network_monitor', 'settings', 'custom_config_local.ini')
########## Load Custom ini configs ##########
from .custom import *
#############################################
INSTALLED_APPS.extend(INSTALLED_FEATURES)
