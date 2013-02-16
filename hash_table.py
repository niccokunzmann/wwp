
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
