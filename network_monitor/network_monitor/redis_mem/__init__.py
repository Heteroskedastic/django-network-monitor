import json
import redis


class RedisMem(object):
    def __init__(self, host='localhost', port=6379, db=0,
                 prefix='redis_mem:', workspace='', json=True):
        self.redis = redis.StrictRedis(host=host, port=port,
                                       db=db, decode_responses=True)
        self._prefix = prefix
        self.workspace = workspace or ''
        self.json = json

    def serialize(self, v):
        if self.json:
            return json.dumps(v)
        return v

    def deserialize(self, v, safe=True):
        if v is None:
            return None
        if isinstance(v, bytes):
            v = v.decode()
        if self.json:
            try:
                v = json.loads(v)
            except Exception:
                if not safe:
                    raise
                v = None
        return v

    def set_workspace(self, ws):
        self.workspace = ws or ''

    @property
    def prefix(self):
        return '%s%s:' % (self._prefix, self.workspace or '')

    def full_key(self, key):
        return '%s%s' % (self.prefix, key)

    def key(self, full_key):
        prefix_len = len(self.prefix)
        return full_key[prefix_len:]

    def ttl(self, key):
        return self.redis.ttl(self.full_key(key))

    def get(self, key):
        return self.deserialize(self.redis.get(self.full_key(key)))

    def set(self, key, value, expire=None):
        full_key = self.full_key(key)
        value = self.serialize(value)
        self.redis.set(full_key, value)
        if expire is not None:
            self.redis.expire(full_key, expire)

    def expire(self, key, duration):
        return self.redis.expire(self.full_key(key), duration)

    def keys(self, remove_prefix=True):
        keys = self.redis.keys('%s*' % self.prefix)
        if remove_prefix:
            return [self.key(k) for k in keys]
        return keys

    def values(self, keys=None):
        if keys is None:
            keys = self.keys(remove_prefix=False)
        else:
            keys = [self.full_key(k) for k in keys]
        if len(keys) == 0:
            return []
        return [self.deserialize(v) for v in self.redis.mget(keys)]

    def getall(self, keys=None):
        if keys is None:
            keys = self.keys(remove_prefix=False)
        else:
            keys = [self.full_key(k) for k in keys]
        if len(keys) == 0:
            return {}
        values = [self.deserialize(v) for v in self.redis.mget(keys)]
        keys = [self.key(k) for k in keys]
        return dict(zip(keys, values))

    def delete(self, key):
        return self.redis.delete(self.full_key(key))

    def clean(self):
        keys = self.keys(remove_prefix=False)
        if keys:
            return self.redis.delete(*keys)
