from functools import wraps


def do_safe(logger=None):
    '''
    a decorator to run a function in safe mode.
    you can be sure your function will not raise any exception.
    usage:
    @do_safe_decorator()
    def f1(a, b):
        ....

    @do_safe_decorator(logger=logging) # to set logging as a logger
    def f2(a, b):
        ....

    '''
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                logger and logger.exception(e)
        return decorator
    return wrapper
