import os
import sys

from .base import CUSTOM_CONFIG_PATH

def load_module_from_source(path, name=""):
    try:
        import importlib.util
    except ImportError:
        import imp
        try:
            return imp.load_source(name, path)
        except FileNotFoundError:
            raise ImportError('Not found: {}'.format(path))
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec:
        raise ImportError('Not found: {}'.format(path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


GLOBAL_CONF_PY_PATH = os.getenv('NETWORK_MONITOR_CONFIG_PATH', '') or CUSTOM_CONFIG_PATH
try:
    _custom_config = load_module_from_source(GLOBAL_CONF_PY_PATH, '')
    self_module = sys.modules[__name__]
    for k in dir(_custom_config):
        if k.isupper():
            setattr(self_module, k, getattr(_custom_config, k))
except ImportError:
    pass
