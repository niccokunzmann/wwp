

def sign_code(code, private_key):
    if hasattr(code, 'encode'):
        code = code.encode('utf8')
    assert type(code) is bytes, 'can only sign bytes'
    assert private_key.can_sign(), 'the key must be able to sign the code'
    (signature,) = private_key.sign()
    return code + ''
    
def is_signed(signed_code, public_key):
    pass

class KeyModule(object):

    def __init__(self, keyRoot):
        self._keyRoot = keyRoot
        self._modules = {}

    def __setattr__(self, name, value):
        if name.startswith('_'):
            return object.__setattr__(self, name, value)
        module = self._keyRoot.get_module_for_key(value, name)
        if getattr(self, name, module) is not module:
            raise AttributeError('You tried to assign %r again. '\
                                 'I only accept the first - for clarity.'\
                                 'Excuse me.' % name)
        self._modules[name] = module

    def __getattribute__(self, name):
        if name.startswith('_'):
            return object.__getattribute__(self, name)
        notFound = []
        subModule = self._keyRoot.get(name, notFound)
        if subModule is notFound:
            raise AttributeError('I could not find a submudule named {0}.'\
                                 'Assign a key to {0} to get the '\
                                 'corresponding module.'.format(name))
        return subModule


import types

class KeyRoot:
    def __init__(self):
        self.key_to_module = {}

    def as_module(self):
        return KeyModule(self)

    def get_module_for_key(self, key, name = None):
        # assume key to string is bijective
        #   can use key if two keys with same string are equal
        index = key.exportKey()
        if name is None:
            name = index
        module = self.get(index, None)
        if module is None:
            module = types.ModuleType(name)
            self.key_to_module[index] = module
            module.__key__ = key
        return module

import inspect

def splitStringByLength(string, length):
    return [string[length * index: length * index + length]
            for index in range((len(string) - 1) // length + 1)]

assert splitStringByLength('12345', 1) == list('12345')
assert splitStringByLength('12345', 2) == ['12', '34', '5']
assert splitStringByLength('12345', 3) == ['123', '45']
assert splitStringByLength('12345', 4) == ['1234', '5']
assert splitStringByLength('12345', 5) == ['12345']
assert splitStringByLength('12345', 6) == ['12345']

class _BaseHashTable(object):
    '''provides the basic functionality of a hash table'''
    
    from Crypto.Hash import SHA256

    def hash(self, source):
        return self.SHA256.new(source).hexdigest()[:5].encode('ascii')

    def __init__(self):
        self.hash_to_object = {}

    def _store(self, source):
        'store one object and return the hash'
        hash = self.hash(source)
        self.hash_to_object[hash] = source
        return hash

    def _get(self, hash):
        return self.hash_to_object[hash]

    def _find(self, *hashes):
        'find the hashes in the hastable and return a list of findings'
        length = None
        for hash in hashes:
            if hash is not None:
                length = len(hash)
                break
        if length is None:
            raise ValueError('I need at least one hash to look for')
        results = []
        for value_hash, value in self.hash_to_object.items():
            if len(value) // length != len(hashes):
                # fix issue that get(hashes[0]) is included
                continue
            for hash1, hash2 in zip(splitStringByLength(value, length), hashes):
                if hash2 is not None and \
                    hash1 != hash2:
                    break
            else:
                results.append(value_hash)
        print(results)
        return results

from functools import partial

class HashTable(_BaseHashTable):
    '''enhances the interface for objects'''

    def store(self, *sources):
        assert len(sources) > 0
        sources = map(self.make_source, sources)
        hashes = list(map(self._store, sources))
        if len(hashes) == 1:
            return hashes[0]
        return self.store(b''.join(hashes))   

    def find(self, *sources):
        assert len(sources) > 0
        sources = list(map(lambda source: (None if source is None
                                           else self.make_source(source)),
                           sources))
        if len(sources) == 1:
            return self._get(hash)
        hashes = map(lambda source: (None if source is None else self.hash(source)), sources)
        found_hashes = self._find(*hashes)
        print('found', found_hashes)
        result_hashes = list(map(lambda h: splitStringByLength(self._get(h), len(h)),
                            found_hashes))
        print('result_hashes', result_hashes)
        return list(map(list, map(partial(map, self._get), result_hashes)))

    @staticmethod
    def make_source(source):
        if hasattr(source, 'encode'):
            source = source.encode('utf8')
        assert type(source) is bytes
        return source


h = HashTable()

assert h.store('1234') == h.store('1234')
hash = h.store(b'12345')
assert h.find(hash) == b'12345'

h.store('hello', 'world')
assert [b'hello', b'world'] in h.find('hello', None), h.find('hello', None)
assert [b'hello', b'world'] in h.find(None, 'world'), h.find(None, 'world')


class Signer:
    
    def __init__(self, private_keys, hash_table):
        self.private_keys = private_keys
        self.hash_table = hash_table

    def getSource(self, object):
        return inspect.getsource(object)
        
    def __call__(self, object):
        source = self.getSource(object)
        source_hash = self.hash_table.store(source)
        hashes = [private_key.sign(source_hash, '') \
                  for private_key in self.private_keys]
        


from pickle import loads, dumps





        
