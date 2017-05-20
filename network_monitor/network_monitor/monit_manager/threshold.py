class BaseMonitoringException(Exception):
    pass


class InvalidThresholdException(BaseMonitoringException):
    pass


class Manager(object):
    _threshold_registry = {}

    @staticmethod
    def get_threshold_cls(name):
        klass = Manager._threshold_registry.get(name)
        if klass is None:
            raise InvalidThresholdException(
                'Invalid Threshold with name "%s"' % name)
        return klass


def register_threshold(name=None):
    '''
    a decorator to register a threshold with a name to system
    '''
    def decorator(cls):
        assert issubclass(cls, Threshold), \
            'cls should be subclass of Threshold'
        threshold_name = name or cls.__name__
        if threshold_name in Manager._threshold_registry:
            raise AssertionError('a Threshold with name=%s already exists' %
                                 threshold_name)
        cls.name = threshold_name
        Manager._threshold_registry[threshold_name] = cls
        return cls
    return decorator


class Threshold(object):
    name = None
    data = None
    trigger_short_message_template = trigger_message_template = \
        '{name}: exceeded!'
    clear_short_message_template = clear_message_template = '{name}: cleared!'

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        if 'trigger_message_template' in kwargs:
            self.trigger_message_template = kwargs.pop(
                'trigger_message_template')
        if 'trigger_short_message_template' in kwargs:
            self.trigger_short_message_template = kwargs.pop(
                'trigger_short_message_template')
        if 'clear_message_template' in kwargs:
            self.clear_message_template = kwargs.pop('clear_message_template')
        if 'clear_short_message_template' in kwargs:
            self.clear_short_message_template = kwargs.pop(
                'clear_short_message_template')

    def message_context(self):
        return {
            'name': self.name,
            'args': self.args,
            'kwargs': self.kwargs,
            'data': self.data,
        }

    @property
    def trigger_short_message(self):
        context = self.message_context()
        return self.trigger_short_message_template.format(**context)

    @property
    def trigger_message(self):
        context = self.message_context()
        return self.trigger_message_template.format(**context)

    @property
    def clear_short_message(self):
        context = self.message_context()
        return self.clear_short_message_template.format(**context)

    @property
    def clear_message(self):
        context = self.message_context()
        return self.clear_message_template.format(**context)

    def satisfied(self, data):
        self.data = data
        return self.check_satisfied()

    def humanize(self):
        return self.name

    def check_satisfied(self):
        raise NotImplementedError


@register_threshold()
class MinMaxThreshold(Threshold):
    trigger_short_message_template = trigger_message_template = \
        '{name}: exceeded! {parameter} {args[0]} {args[1]}'
    clear_short_message_template = clear_message_template = \
        '{name}: cleared!  {parameter} {args[0]} {args[1]}'

    COMPARATORS = {
        '>': lambda a, b: a > b,
        '<': lambda a, b: a < b,
        '==': lambda a, b: a == b,
        '>=': lambda a, b: a >= b,
        '<=': lambda a, b: a <= b
    }

    def __init__(self, operator, condition_value, parameter=None, **kwargs):
        assert operator in self.COMPARATORS, \
            'Invalid operator "{}": valids are {}'.format(operator,
                                                          self.COMPARATORS)
        super(MinMaxThreshold, self).__init__(operator, condition_value,
                                              parameter=parameter, **kwargs)

    def message_context(self):
        ctx = super(MinMaxThreshold, self).message_context()
        parameter = self.kwargs.get('parameter')
        ctx['parameter'] = parameter or 'data'
        value = (self.data or {}).get(parameter) if parameter else self.data
        ctx['value'] = value
        return ctx

    def check_satisfied(self):
        if not self.data:
            return False

        operator, condition_value = self.args
        parameter = self.kwargs.get('parameter')
        value = self.data
        if parameter:
            if parameter not in self.data:
                return False
            value = self.data.get(parameter)
        return self.COMPARATORS.get(operator)(value, condition_value)

    def humanize(self):
        parameter = self.kwargs.get('parameter') or 'data'
        return '{} {} {}'.format(parameter, self.args[0], self.args[1])
