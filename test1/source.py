import linecache
import hashlib

def get(module):
    lines = linecache.getlines(module.__file__, module.__dict__)
    lines[-1] = lines[-1][:-1]
    return ''.join(lines)

def hashes(module):
    return [hashlib.sha1(get(module).encode('utf-8')).hexdigest()]
