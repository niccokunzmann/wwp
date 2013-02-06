

def sign_code(code, private_key)
    if hasattr(code, 'encode'):
        code = code.encode('utf8')
    assert type(code) is bytes, 'can only sign bytes'
    assert private_key.can_sign(), 'the key must be able to sign the code'
    (,signature) = private_key.sign()
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

class _BaseHashTable(object):
    '''provides the basic functionality of a hash table'''
    
    from Crypto.Hash import SHA256

    def hash(self, source):
        source = make_source(source)
        return self.SHA256.new(source).digest()

    def __init__(self):
        self.hash_to_object = {}

    def _store(self, source, *sources):
        'store one object and return the hash'
        source = self.make_source(source)
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
        for value_hash, value in self.hash_to_object.itmes():
            for index, hash in enumerate(hashes):
                if hash is not None and \
                    value[index * length:index * length + length] != hash:
                    break
            else:
                results.append(value_hash)
        return results

class HashTable(_BaseHashTable):
    '''enhances the interface for objects'''

    def store(self, *sources):
        assert len(sources) > 0
        sources = map(self.make_source, sources)
        hashes = map(self._store, sources)
        if len(hashes) == 1:
            return hashes[0]
        return self.store(b''.join(hashes))   

    def find(self, *sources):
        assert len(sources) > 0
        sources = map(self.make_source, sources)
        if len(sources) == 1:
            return self._get(hash)
        hashes = map(lambda source: (None if source is None else self.hash(source)))
        return map(self.get, self.find_hashes(*hashes))

    @staticmethod
    def make_source(source)
        if hasattr(source, 'encode'):
            source = source.encode('utf8')
        assert type(source) is bytes
        return source


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





        
