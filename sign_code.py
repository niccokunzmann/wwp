

def sign_code(code, private_key):
    if hasattr(code, 'encode'):
        code = code.encode('utf8')
    assert type(code) is bytes, 'can only sign bytes'
    assert private_key.can_sign(), 'the key must be able to sign the code'
    (signature,) = private_key.sign()
    return code + ''
    
def is_signed(signed_code, public_key):
    pass


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

    def _includes(self, hash):
        return hash in self.hash_to_object

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
        return results

import os
import base64

class FileCachingHashTable(_BaseHashTable):

    directory = b'./table/'

    if not os.path.isdir(directory):
        os.mkdir(directory)

    def _getFilePath(self, hash):
        assert type(hash) is bytes, hash
        return os.path.join(self.directory, base64.b16encode(hash))
    
    def _store(self, source):
        # todo: faster
        hash = _BaseHashTable._store(self, source)
        path =  self._getFilePath(hash)
        if not os.path.isfile(path):
            open(path, 'wb').write(source)
        return hash

    def _get(self, hash):
        try:
            return _BaseHashTable._get(self, hash)
        except KeyError:
            path = self._getFilePath(hash)
            if os.path.isfile(path):
                _BaseHashTable._store(self, open(path, 'rb').read())
            return _BaseHashTable._get(self, hash)

    # official interface

    def getFile(self, source):
        return os.path.join(self._getFilePath(self._store(source)))


from functools import partial

class HashTable(FileCachingHashTable):
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
        if len(sources) == 1: return self._get(sources[0])
        hashes = map(lambda source: (None if source is None else self.hash(source)), sources)
        found_hashes = self._find(*hashes)
        result_hashes = list(map(lambda h: splitStringByLength(self._get(h), len(h)),
                            found_hashes))
        return list(map(list, map(partial(map, self._get), result_hashes)))

    @staticmethod
    def make_source(source):
        if hasattr(source, 'encode'):
            source = source.encode('utf8')
        assert type(source) is bytes, 'Expected bytes, got %r' % source
        return source

    def print(self):
        for x, y in self.hash_to_object.items():
            print(x)
            print(y)
            print()

    def getFile(self, source):
        return FileCachingHashTable.getFile(self, self.make_source(source))

h = HashTable()

assert h.store('1234') == h.store('1234')
hash = h.store(b'12345')
assert h.find(hash) == b'12345', h.find(hash)

h.store('hello', 'world')
assert [b'hello', b'world'] in h.find('hello', None), h.find('hello', None)
assert [b'hello', b'world'] in h.find(None, 'world'), h.find(None, 'world')

import types

def hashToSignatureBytes(hash, private_key):
    signature = str(private_key.sign(hash, '')[0]).encode('utf8')
    assert signature.isdigit(), 'The signature is expected to be a number'\
                                ', not %r' % signature
    return signature

def verifyHashSignatureBytes(hash, signature, public_key):
    assert signature.isdigit(), 'The signature is expected to be a number'\
                                ', not %r' % signature
    signature = (int(signature),)
    return public_key.verify(hash, signature)


import Crypto.PublicKey.RSA

private_key = Crypto.PublicKey.RSA.importKey(b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCsDtPjibKg0LjJBwo4O7Ea6zZIJUvVXsA+i2gl+IHuDRRjpuDs\n+7Tx1W404Mw8gj5I0xRwwHBFbHxvkV5EbZcLHB4SMg2SVe7nvxVOoenfEPQ44aJ2\nUimR66Oak2zoHdJEYeGSyF1rXDLwDkrTP0GbC7fJ7mpmUkirLaKEym0d1wIDAQAB\nAoGAaDSiyBBBi3xeLgKBggVFAlSqj49nGldEf5zW+whDSPXK/3+2glEACeeF06jC\niXMoXdrZamBinulRhBC60x68dxLPxq1U8cNSsHSWy9ZM9JoETwUzH2W69dkpU6XI\n1B3dekYbFXnOqJM7TE0X5IwLuyEM/1U0j/wl/JzigpFq3iECQQC/qcZx0GyvHoQ6\ns2DyLXzNyqknY5strxt1eIx36yTiyTE8YnSEgpbu+l2DRuse8f9DrmI8i/fnGk3c\n/ZRUyjIzAkEA5dBPYaM8+MyZBzZaDzzD1ufEqBhi6lAhP3ReoXnoVmXEuKSvCpS4\nMNPBG2i3oAnNfYeIPQ2imtGJO0nmPmRpzQJAKT3I+7iTimMQpOjwVWxATK/tEhK2\n02+4guB7qVopx7rvI0U0OUc4Xxf0g0kBUtlTyiZ98PVVVJ8uXf0aq9wOTQJBAIdy\naPbg4PS6kY7Ap//HDp3A6BUymkoDhDUD/yoo0ZjqTjGNTmVsFcshYvUmmONII8bS\ndKeXO7kHulwpR/yJ7hkCQBgMbXfk1uviwfHyjcZM3iSZe4AzJlPCxurE6t5DInkx\notvCO4ws1C2Rak1IEsbqU6LxUBe+hdpjNsAXTkyVw3k=\n-----END RSA PRIVATE KEY-----')
public_key = private_key.publickey()

signature = hashToSignatureBytes(b'12345', private_key)
assert verifyHashSignatureBytes(b'12345', signature, public_key)

import inspect

class SecurityException(Exception):
    pass

class VerificationException(SecurityException):
    pass

class SourceCodeVerificationException(VerificationException):
    pass

class SubModule(types.ModuleType):

    hashToSignatureBytes = staticmethod(hashToSignatureBytes)

    def __init__(self, name, key, hash_table):
        types.ModuleType.__init__(self, name)
        self._hash_table = hash_table
        self.__key__ = key
        self.__exported_key__ = key.exportKey()
        self.require = self.require
        self.signed = self.signed

    def signed(self, obj):
        '''this is kind of an assertion'''
        local_source = inspect.getsource(obj)
        if local_source == '':
            raise ValueError('could not find source of %r' % obj)
        name = obj.__name__
        for source, name in self.yieldVerifiedSourcesOfName(name):
            if source == local_source:
                return obj
        raise SourceCodeVerificationException('Source of %r is not trusted' % \
                                              obj)

    def __getattribute__(self, name):
        if name.startswith('_') or name in self.__dict__ or \
           name in ('require', 'signed', 'execute', '__dict__', 
                    'yieldVerifiedSourcesOfName'):
            return types.ModuleType.__getattribute__(self, name)
        self.require(name)
        return getattr(self, name)

    def yieldVerifiedSourcesOfName(self, name):
        attacker = []
        # now save: public_key, signature, source, name
        query = self.__exported_key__, None, None, name.encode('utf8')
        results = self._hash_table.find(*query)
        for public_key, signature, source, name in results:
            assert self.__exported_key__ == public_key, "%r == %r" % \
                   (self.__exported_key__, public_key)
            hash = self._hash_table.store(source, name)
            if verifyHashSignatureBytes(hash, signature, self.__key__):
                yield source.decode('utf8'), name.decode('utf8')
            else:
                attacker_string = 'Someone tried to attack %r of %s '\
                                  'with source \n%s' % \
                                  (name, public_key, source)
                attacker.append(attacker_string)
                print(attacker_string)
        raise AttributeError('Could not find attribute %r in the tables. ' % name + \
                             "\n".join(attacker))
        

    def require(self, name, reload = False):
        if not reload and name in self.__dict__:
            return getattr(self, name)
        for source, name in self.yieldVerifiedSourcesOfName(name):
            return self.execute(source, name)

    def execute(self, source, name):
        assert type(source) is str
        assert type(name) is str
        source_file = self._hash_table.getFile(source)
        source_code = compile(source, source_file, 'exec')
        exec(source_code, self.__dict__)
        return self.__dict__[name]

class KeyModule(object):

    def __init__(self, keyRoot):
        self._keyRoot = keyRoot
        self._modules = {}

    def __setattr__(self, name, value):
        if name.startswith('_'):
            return object.__setattr__(self, name, value)
        module = self._keyRoot.getModuleForKey(value, name)
        if getattr(self, name, module) is not module:
            raise AttributeError('You tried to assign %r again. '\
                                 'I only accept the first - for clarity.'\
                                 'Excuse me.' % name)
        self._modules[name] = module

    def __getattribute__(self, name):
        if name.startswith('_'):
            return object.__getattribute__(self, name)
        notFound = []
        subModule = self._modules.get(name, notFound)
        if subModule is notFound:
            raise AttributeError('I could not find a submudule named {0}.'\
                                 'Assign a key to {0} to get the '\
                                 'corresponding module.'.format(name))
        return subModule


class KeyRoot:

    newSubModule = SubModule
    
    def __init__(self, hash_table):
        self.key_to_module = {}
        self.hash_table = hash_table

    def asModule(self):
        return KeyModule(self)

    def getModuleForKey(self, key, name = None):
        # assume key to string is bijective
        #   can use key if two keys with same string are equal
        index = key.exportKey()
        if name is None:
            name = index
        module = self.key_to_module.get(index, None)
        if module is None:
            module = self.newSubModule(name, key, self.hash_table)
            self.key_to_module[index] = module
        return module

h = HashTable()

k = KeyRoot(h)
m = k.asModule()
m.a = public_key
assert m.a.__name__ == 'a', m.a.__name__
assert m.a.__key__ == public_key, m.a.__key__
assert m.a == m.a

import inspect


class Signer:
    
    def __init__(self, private_keys, hash_table):
        self.private_keys = [(  private_key,
                                private_key.publickey().exportKey())
                             for private_key in private_keys]
        self.hash_table = hash_table

    def getSource(self, obj):
        return inspect.getsource(obj)
        
    hashToSignatureBytes = staticmethod(hashToSignatureBytes)

    def __call__(self, obj):
        source = self.getSource(obj)
        name = obj.__name__
        self.store_source_with_name(source.encode('utf8'), name.encode('utf8'))
        return obj

    def store_source_with_name(self, source, name):
        for private_key, public_key in self.private_keys:
            # now save: source, name
            hash = self.hash_table.store(source, name)
            signature = self.hashToSignatureBytes(hash, private_key)
            # now save: public_key, signature, source, name
            # TODO: make secure
            self.hash_table.store(public_key, signature, source, name)

        
signed = Signer([private_key], h)
s2 = Signer([], h)

@signed
def f():
    return '123'

assert m.a.f() == '123', m.a.f()


@signed
def g():
    raise ValueError('')

try:
    m.a.g()
except ValueError:
    import traceback
    import io
    s = io.StringIO()
    traceback.print_exc(file = s)
    s = s.getvalue()
    assert "raise ValueError('')" in s, s
else:
    assert False, 'There should be an error'


from pickle import loads, dumps
