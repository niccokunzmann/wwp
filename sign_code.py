
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

    def includes(self, hash):
        return hash in self.hash_to_object

    def store(self, source):
        'store one object and return the hash'
        hash = self.hash(source)
        self.hash_to_object[hash] = source
        return hash

    def get(self, hash):
        return self.hash_to_object[hash]

    def find(self, *hashes):
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
    
    def print(self):
        for x, y in self.hash_to_object.items():
            print(x)
            print(y)
            print()

import os
import base64

class FileCachingHashTable(_BaseHashTable):

    directory = b'./table/'

    if not os.path.isdir(directory):
        os.mkdir(directory)

    def _getFilePath(self, hash):
        assert type(hash) is bytes, hash
        return os.path.join(self.directory, base64.b16encode(hash))
    
    def store(self, source):
        # todo: faster
        hash = _BaseHashTable.store(self, source)
        path =  self._getFilePath(hash)
        if not os.path.isfile(path):
            open(path, 'wb').write(source)
        return hash

    def get(self, hash):
        try:
            return _BaseHashTable.get(self, hash)
        except KeyError:
            path = self._getFilePath(hash)
            if os.path.isfile(path):
                _BaseHashTable.store(self, open(path, 'rb').read())
            return _BaseHashTable.get(self, hash)

    def getFile(self, source):
        return self._getFilePath(self.store(source))



from functools import partial

class HashTable:
    '''enhances the interface for objects'''

    def __init__(self):
        self.ht = FileCachingHashTable()
        self._store = self.ht.store
        self._find = self.ht.find
        self.print = self.ht.print
        self._hash = self.ht.hash
        self._get = self.ht.get
        self._getFile = self.ht.getFile

    def hash(self, source):
        return self._hash(self.make_source(source))

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


    def getFile(self, source):
        return self._getFile(self.make_source(source))



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


from collections.abc import MutableMapping

class SignedModuleDict(MutableMapping, dict):
    AccessError = KeyError

    __slots__ = ('sub_module',)

    def __init__(self, sub_module):
        self.sub_module = sub_module

    def __contains__(self, name):
        return hasattr(self.sub_module, name)
        
    def __getitem__(self, name):
        try:
            return getattr(self.sub_module, name)
        except AttributeError as e:
            raise self.AccessError(*e.args)

    def __setitem__(self, name, value):
        return setattr(self.sub_module, name, value)

    def __delitem__(self, name):
        return delattr(self.sub_module, name)

    def __len__(self):
        return len(dir(self.sub_module))

    def __iter__(self):
        return iter(dir(self.sub_module))

    def __eq__(self, other):
        return self is other

class SignedModuleNamespace(SignedModuleDict):
    AccessError = NameError

assert SignedModuleDict.mro().index(dict) > SignedModuleDict.mro().index(MutableMapping)

import inspect

class SecurityException(Exception):
    pass

class VerificationException(SecurityException):
    pass

class SourceCodeVerificationException(VerificationException):
    pass

class ImmutableStateException(SecurityException):
    pass

class SignedModule(types.ModuleType):

    hashToSignatureBytes = staticmethod(hashToSignatureBytes)

    __frozen = False

    def __init__(self, name, key, hash_table):
        types.ModuleType.__init__(self, name)
        self.__dict = SignedModuleDict(self)
        self.__namespace = SignedModuleNamespace(self)
        self._hash_table = hash_table
        self.__key__ = key
        self.__exported_key__ = key.publickey().exportKey()
        self.__frozen = True
        
    @property
    def asDict(self):
        return self.__dict

    @property
    def asNamespace(self):
        return self.__namespace

    # todo: move many methods to signer

    def signed(self, obj, name = None):
        '''this is kind of an assertion'''
        if name is None:
            name = obj.__name__
        if obj.__module__ == __builtins__.__name__ and \
           getattr(__builtins__, name, []) is obj:
            return obj
        local_source = inspect.getsource(obj)
        if local_source == '':
            raise ValueError('could not find source of %r' % obj)

        for source, name in self.yieldVerifiedSourcesOfName(name):
            if source == local_source:
                return obj
        raise SourceCodeVerificationException('Source of %r is not trusted' % \
                                              obj)

    def __getattribute__(self, name):
        if name.startswith('_') or name in self.__dict__ or \
           hasattr(self.__class__, name):
            return types.ModuleType.__getattribute__(self, name)
        self.require(name)
        return getattr(self, name)

    def __setattr__(self, name, obj):
        if not self.__frozen:
            return types.ModuleType.__setattr__(self, name, obj)
        if name in self.__dict__:
            raise ImmutableStateException('tried to modify immutable attribute'
                                          ' %r of %r' % (name, self))
        if self.__key__.has_private():
            # this should ask can_sign() but impossible to use here
            Signer([self.__key__], self._hash_table).sign(obj, name)
            if hasattr(obj, '__globals__') and obj.__globals__ != self.asNamespace:
                self.require(name)
        else:
            self.signed(obj, name)
            if hasattr(obj, '__globals__'):
                if obj.__globals__ != self.asNamespace:
                    raise LookupError('this object is not scoped correctly.'
                                      ' It should point to %s.asNamespce' % self)
            else:
                raise TypeError('I can not handle this type of object like %r' % obj)
        types.ModuleType.__setattr__(self, name, obj)
        

    def yieldVerifiedSourcesOfName(self, name):
        attacker = []
        # now save: public_key, signature, source, name
        query = self.__exported_key__, None, None, name.encode('utf8')
        results = self._hash_table.find(*query)
        for public_key, signature, source, name in results:
            assert self.__exported_key__ == public_key, "%r == %r" % \
                   (self.__exported_key__, public_key)
            # todo: assertion for name
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
        try:
            source_code = compile(source, source_file, 'exec')
        except IndentationError:
            source = 'if 1:\n' + source
            source_code = compile(source, source_file, 'exec')
        exec(source_code, self.asNamespace)
        return self.__dict__[name]

    @property
    def asContext(self):
        return NamespaceIncluder(self)

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
        SignedModule = self._modules.get(name, notFound)
        if SignedModule is notFound:
            raise AttributeError('I could not find a SignedModule named {0}. '\
                                 'Assign a key to {0} to create the '\
                                 'corresponding module.'.format(name))
        return SignedModule


class KeyRoot:

    newSignedModule = SignedModule
    
    def __init__(self, hash_table):
        self.key_to_module = {}
        self.hash_table = hash_table

    @property
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
            module = self.newSignedModule(name, key, self.hash_table)
            self.key_to_module[index] = module
        return module

h = HashTable()

k = KeyRoot(h)
m = k.asModule
m.a_public = public_key
assert m.a_public.__name__ == 'a_public', m.a_public.__name__
assert m.a_public.__key__ == public_key, m.a_public.__key__
assert m.a_public == m.a_public

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
        return self.sign(obj)

    def sign(self, obj, name = None):
        source = self.getSource(obj)
        if name is None:
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

        
m.a_private = private_key

assert m.a_public != m.a_private
assert m.a_public.asDict != m.a_private.asDict
assert m.a_public.asNamespace != m.a_private.asNamespace

def f():
    return '123'

m.a_private.f = f

assert m.a_public.f() == '123', m.a_public.f()



def g():
    raise ValueError('')

m.a_private.g = g

# todo: raise if different stuff added twice
try:
    m.a_public.g()
except ValueError:
    import traceback
    import io
    s = io.StringIO()
    traceback.print_exc(file = s)
    s = s.getvalue()
    assert "raise ValueError('')" in s, s
else:
    assert False, 'There should be an error'

def dependency():
    return 1


def using_dependency():
    return dependency() + 1

m.a_private.dependency = dependency
m.a_private.using_dependency = using_dependency

assert m.a_public.using_dependency() == 2
assert m.a_public.using_dependency.__globals__ == m.a_public.asNamespace
    

def test_access():
    return 5

m.a_private.test_access = test_access
try:
    m.a_private.test_access = test_access # wrong
    assert False
except ImmutableStateException:
    pass

try:
    m.a_public.v = test_access
    assert False, 'set attibute of publickey'
except AttributeError:
    pass

try:
    m.a_public.test_access = test_access
    assert False, 'can not set attribute to wrongly scoped object'
except LookupError:
    pass

assert m.a_public.test_access() == 5

try:
    m.a_public.in_with
    assert False, 'AttributeError if accessing module'
except AttributeError:
    pass

try:
    m.a_public.asDict['in_with']
    assert False, 'KeyError if accessing dict'
except KeyError:
    pass

try:
    exec('in_with', m.a_public.asNamespace)
    assert False, 'NameError if accessing in exec'
except NameError as e:
    assert e.args == ("Could not find attribute 'in_with' in the tables. ",), e.args
    
   
class NamespaceIncluder:
    def __init__(self, sub_module):
        self.sub_module = sub_module

    def getLocals(self):
        # 0 is here
        # 1 is __enter__ and __exit__
        # 2 is outside
        frame = inspect.stack()[2][0]
        return frame.f_locals.copy()

    def __enter__(self):
        self._locals = self.getLocals()

    def __exit__(self, ty, error, tb):
        oldLocals = self._locals
        newlocals = self.getLocals()
        dict = self.sub_module.asDict
        if error is None:
            for key, value in newlocals.items():
                if key not in oldLocals or value != oldLocals[key]:
                    dict[key] = value
        
def not_in_with():
    return None

with m.a_private.asContext:
    def in_with():
        return 'with'

assert m.a_public.in_with() == 'with'
assert m.a_private.in_with() == 'with'

assert not hasattr(m.a_public, 'not_in_with')

# TODO
# add signed classes
# adding a class means trusting all superclasses, their modules and imported modules
# TODO: add module import support for keys,
# TODO: import module should be possible in SignedModule
# TODO: !!!!!!!!! load functions with with m.a_private.asContext:
#                 sign every other function relative to its module !!!!!!!!!
# todo: remove this test and sign things when serializer is ready
assert m.a_public.signed(object, 'object'), 'built in objects must be trusted'
try:
    m.a_public.signed(object, 'asdas')
    assert False, 'wrong names for builtin objects not good'
except TypeError:
    pass

##from Crypto.PublicKey import RSA
##from Crypto import Random
##rng = Random.new().read
##RSAkey = RSA.generate(1024, rng) 

untrusted_key = Crypto.PublicKey.RSA.importKey(b'-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQCmPu3/VDfsB4omSF1p3afqD+gCKBoiQsThSw34gm78mKpVvmwB\nUh640+jL8tZhi4Dd3xunRFSG2KsGs4rcueWNiM/jwlA2sYDQ45qWWBvnumvQGwSn\nkuw1KQ3Ey/A33zA8oWVwBBGJg9WENrLke4jCS8iCWWLPNj1/CKIm050c1QIDAQAB\nAoGAIitBA3+t1sdd76xj9sRmJMeMKhVP+ca7bIrenjtA0I4YRHNVA5h7VAXKDVEm\nGvpvTCr1JhX3QZf63u+8FM3oji/H5GNiihQ3YsYFlh/ZHnoE73YrxrVb9ROcakRq\nXBRRLmnLeLW+Ok6IQ3kKyL7w0+kSqgGNnoiUkEbY93bExYECQQDMZcgx90ezO73l\nSI8WjDcoPToCOTYzTybiMrxpmJJJ1Y3m7BuZXGDQedynWJFIYO3PvACV8DNs71Uz\nNOPrS4tRAkEA0DdmCjqmQ9bJh9XOvtHlzUyf2DEHJp+OYUhQoEmS1Nh7qXKN50mz\n4Vb6qfSJhZu1ILyqIFoqjLInCDka7POQRQJAGJEfN8o15vgGQfmvoREnTAHX6A6C\nUjZwQP3CIZsB8jflv1yfkJZG2Kfc+owtohpsWuyI0Xy2YaB+iBISVuSUkQJAVsaP\nxzmUK3ere+n2hP5TSJFjmKUuNsGOhCqwN20SPZSPTRpJ25eS2Rn307bvTXiMLz2R\npXQOgZ6Jt9qcxx3nBQJAQfpNKDZRDsEtKQlmHafkFFmViBqgi9+9kJp7VmnWgxdT\niP+7yCmdVQmUZ7JPSubluqy/aj4QK2y4CQ+t8yuD1w==\n-----END RSA PRIVATE KEY-----')
untrusted_public_key = untrusted_key.publickey()
m.u_private = untrusted_key
m.u_public = untrusted_public_key




# TODO
# add imports: 
# m.a_private.trust(key_or_module)
# m.a_private.attribute = m.a_private.trust(key)

