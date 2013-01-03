import unittest
import types
import source
import sys
import os
import linecache
import hashlib
import magnetlink

TMP = 'tmp'

def create_module(name, source):
    if not os.path.isdir(TMP):
        os.mkdir(TMP)
    with open(os.path.join(TMP, name + '.py'), 'wb') as f:
        f.write(source.encode('utf-8'))
    if not TMP in sys.path:
        sys.path.insert(0, TMP)

def import_module(module_source):
    def wrapper(function):
        def wrap(self):
            module_name = function.__name__
            sys.modules.pop(module_name, None)
            create_module(module_name, module_source)
            __import__(module_name)
            self.source = module_source
            self.module = module = sys.modules[module_name]
            with open(module.__file__, 'rb') as f:
                self.raw_source = f.read()
            return function(self)
        wrap.__name__ = function.__name__
        return wrap
    return wrapper

class Test_import_module(unittest.TestCase):

    @import_module('a = 2')
    @import_module('a = 1')
    def test_reload_module(self):
        self.assertEqual(self.module.a, 2)

    @import_module('a = "alli"')
    def test_module(self):
        self.assertEqual(self.module.a, "alli")
        self.assertEqual(self.module.__name__, "test_module")

    @import_module('a = "\u1234"')
    def test_raw_source(self):
        self.assertEqual(self.raw_source, self.source.encode('utf-8'))

    @import_module('''a = "alli2"''')
    def test_module_import(self):
        import test_module_import
        self.assertIs(self.module, test_module_import)

    @import_module('a = "alli3"')
    def test_source(self):
        self.assertEqual(self.source, 'a = "alli3"')

    @import_module('a = "alli3"\n')
    def test_source_with_newline(self):
        self.assertEqual(self.source, 'a = "alli3"\n')    

    @import_module('a = "\u1234"')
    def test_read_file(self):
        with open(self.module.__file__)as f:
            self.assertEqual(f.read(), self.source)

class Test_source(unittest.TestCase):

    @import_module('''def f(): return ":)"''')
    def test_get_source(self):
        import test_get_source
        self.assertEqual(source.get(test_get_source), self.source)

    @import_module('smile = "Just smile, do not look away!"')
    def test_get_hash(self):
        hexdigest = hashlib.sha1(self.raw_source).hexdigest()
        self.assertIn(hexdigest, source.hashes(self.module))

class Test_magnet(unittest.TestCase):
    pass
    
        
if __name__ == '__main__':
    unittest.main(exit = False)
