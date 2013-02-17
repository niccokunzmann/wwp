
import sys
import inspect
import threading
import gc
import types
import magicMethods
from weakref import WeakKeyDictionary

__import = __import__


class ModuleTransformationJump(Exception):
    def __init__(self, message, cls, role):
        Exception.__init__(self, message)
        self.cls = cls
        self.role = role
    

def _import_(*args, **kw):
##    print('import', args)
    try:
        return __import(*args, **kw)
    except ModuleTransformationJump:
        ty, err, tb = sys.exc_info()
        while inThisModule(tb):
            tb = tb.tb_next

if hasattr(__builtins__, '__setitem__'):
    __builtins = __builtins__
else:
    __builtins = __builtins__.__dict__

__builtins['__import__'] = _import_

imported = threading.local

def inThisModule(tb_or_frame):
    if hasattr(tb_or_frame, 'tb_frame'):
        # tb
        tb_or_frame = tb_or_frame.tb_frame
    return tb_or_frame.f_globals is globals()

def getCallerRoles():
    stack = inspect.stack()
    while stack and inThisModule(stack[0][0]):
        stack.pop(0)
    if not stack:
        return {}
    frame = stack[0][0]
##    print('module', frame.f_globals['__name__'])
    # todo: dispatch type and role
    roles = frame.f_globals.get('__roles__', {})
    return roles    
    

class BaseRolable:

    def __init__(self):
        try:
            self.__initializedRoles
        except AttributeError:
            self.__initializedRoles = []
 
    def changeToRole(self, role):
        self.__class__ = role
        print('change', id(self), self)
        if role not in self.__initializedRoles:
            role.__init__(self)

    def toTransformFunction():
        return False

    def __getattribute__(self, name):
##            print('getattr1', name)
        roles = getCallerRoles()
##            print('roles', roles, Rolable)
        role = roles.get(type(self).selfclass, None)
##            print('role', role is type(self), role, type(self))
        if role is None or role is type(self):
            cls = type(self).superclass
            return super(cls, self).__getattribute__(name)
        self.__class__ = role
        self.changeToRole(role)
        return getattr(self, name)

def rolable(cls, baseclass = BaseRolable):
    assert not isBuiltIn(cls)
    return _rolable(cls, baseclass)

def _rolable(cls, baseclass):
    # just for real classes, no builtin types!
    class Rolable(baseclass, cls):
        superclass = cls
        def __init__(self, *args, **kw):
            if cls.__init__ != object.__init__:
                cls.__init__(self, *args, **kw)
            else:
                object.__init__(self)
            baseclass.__init__(self, *args, **kw)
    Rolable.selfclass = Rolable  
    Rolable.__module__ = cls.__module__
    Rolable.__name__ = cls.__name__
    Rolable.__qualname__ = cls.__qualname__
    return Rolable

__undefined = object()

def isBuiltIn(cls):
    return __builtins.get(cls.__name__, __undefined) is cls

def roleOf(cls):
    if issubclass(cls, BaseRolable):
        # first this: might have rolable in builtins
        return roleOfRolable(cls)
    elif isBuiltIn(cls):
        # cls is an builtin thing
        return roleOfBuiltin(cls)
    # todo: better description
    raise ValueError('cannot handle roles for %r' % cls)

def roleOfRolable(rolable):
    def makeRole(role):
        module = sys.modules[role.__module__]
        if not hasattr(module, '__roles__'):
            module.__roles__ = {}
        roles = module.__roles__
        # todo: what if class role(role)
        class Role(role, rolable):
            # somehow one has to avoid that the role calls the
            # rolable __init__
            if not hasattr(role, '__init__'):
                def __init__(self):
                    pass
        Role.__name__ = role.__name__
        if rolable in roles:
            raise ValueError('can not have two roles for one object')
        roles[rolable] = Role # cls is the role of base in the modules context
        return role
    return makeRole



def transformFunction(function, cls, rolable):
    "transform a function to use the role instead of the builtin type"
    code = transformCode(function.__code__, cls, rolable)
    function.__code__ = code
    return function
    
def transformCode(code, cls, rolable):
##class code(object)
## |  code(argcount, kwonlyargcount, nlocals, stacksize, flags, codestring,
## |        constants, names, varnames, filename, name, firstlineno,
## |        lnotab[, freevars[, cellvars]])
## |  co_argcount
## |  
## |  co_cellvars
## |  
## |  co_code
## |  
## |  co_consts
## |  
## |  co_filename
## |  
## |  co_firstlineno
## |  
## |  co_flags
## |  
## |  co_freevars
## |  
## |  co_kwonlyargcount
## |  
## |  co_lnotab
## |  
## |  co_name
## |  
## |  co_names
## |  
## |  co_nlocals
## |  
## |  co_stacksize
## |  
## |  co_varnames
    consts = list(code.co_consts)
    changed = False
    for index, const in enumerate(consts):
        print('const:', const, type(const) == cls, type(const), cls)
        if type(const) == cls:
            const = makeRolable(const)
            consts[index] = const
            changed = True
    consts = tuple(consts)

    if not changed:
        return code

    return types.CodeType(code.co_argcount,
                          code.co_kwonlyargcount, 
                          code.co_nlocals,
                          code.co_stacksize,
                          code.co_flags,
                          code.co_code,
                          consts,
                          code.co_names,
                          code.co_varnames,
                          code.co_filename,
                          code.co_name,
                          code.co_firstlineno,
                          code.co_lnotab,
                          code.co_freevars,
                          code.co_cellvars)

def getMagicMethod(name):
    def magicMethod(self, *args, **kw):
        print('magicMethod', name)
        function = getattr(self._actualValue, name)
        value = function(*args, **kw)
        return makeRolable(value)
    magicMethod.__name__ = name
    magicMethod.__qualname__ = 'BuiltInTypeProxy.' + name
    return magicMethod
    
class _BuiltInTypeProxy(BaseRolable):
    pass

for magicMethodName in magicMethods.magicMethods:
    setattr(_BuiltInTypeProxy, magicMethodName, getMagicMethod(magicMethodName))


class BuiltInTypeProxy(_BuiltInTypeProxy):
    #
    # Toni Mattis stated that this could be changed by writing a 
    # C-extension goes dirctly into the class of the type.
    # "".__class__ = ... # would be possible
    #
    # This is a pure python solution to this problem.
    # Just a proxy.
    # 

    def __init__(self, actualValue):
        print('init', type(self), actualValue)
        dict = object.__getattribute__(self, '__dict__')
        dict['__local_attributes_set'] = set(['_actualValue'])
        dict['__local_attributes_get'] = set(['_actualValue'])
        dict['_actualValue'] = actualValue
        _BuiltInTypeProxy.__init__(self)

    def __setattr__(self, name, value):
        dict = object.__getattribute__(self, '__dict__')
        if name in dict['__local_attributes_set']:
            return BaseRolable.__setattr__(self, name, value)
        try:
            return setattr(self._actualValue, name, value)
        except:
            ty, err, tb = sys.exc_info()
            if tb.tb_next == None:
                dict['__local_attributes_set'].add(name)
                return setattr(self, name, value)
            else:
                raise err.with_traceback(tb)

    def __getattribute__(self, name):
        print('getattr', name, type(self))
        dict = object.__getattribute__(self, '__dict__')
        if name == '_actualValue':
            return object.__getattribute__(self, name)
        if name in dict['__local_attributes_get']:
            return makeRolable(BaseRolable.__getattribute__(self, name))
        try:
             attribute = getattr(self._actualValue, name)
        except:
            ty, err, tb = sys.exc_info()
            if tb.tb_next == None:
                dict['__local_attributes_get'].add(name)
                attribute = BaseRolable.__getattribute__(self, name)
            else:
                raise err.with_traceback(tb)
        return makeRolable(attribute)

    def __str__(self):
        return '!' + str(self._actualValue)

    def __contains__(self, other):
        # todo: type that returns 5 times itself and then a bool
        return other in self._actualValue

    @staticmethod
    def toTransformFunction():
        return True

__builtInsToRolables = {} # cls: 

def rolableOfBuiltIn(cls):
    RolableFor_ = __builtInsToRolables.get(cls)
    if RolableFor_ is None:
        RolableFor_ = _rolable(cls, BuiltInTypeProxy)
        __builtInsToRolables[cls] = RolableFor_
        __builtInsToRolables[RolableFor_] = lambda x: x
        RolableFor_.__name__ = '_rolable'
        RolableFor_.__qualname__ += '_rolable'
    return RolableFor_

def roleOfBuiltin(builtinClass):
    # todo: transform module?
    def makeRole(role):
        raise ModuleTransformationJump('module needs transformation for ' 
                                       'builtin type',
                                       builtinClass,
                                       role)
    return roleOfRolable(rolableOfBuiltIn(builtinClass))


def builtInProxy(obj):
    return rolableOfBuiltIn(type(obj))(obj)

__rolables = WeakKeyDictionary()

def realType(obj):
    cls = type(obj)
    if issubclass(cls, BaseRolable):
        return obj.__class__
    return cls

def makeRolable(obj):
    print('makeRolable:', type(obj), realType(obj), obj)
    if obj in __rolables:
        return __rolables[obj]
    if realType(obj) in (bool, types.MethodType, types.FunctionType, type):
        # we can do nothing for bool but maybe for
        # methods and functions in future
        # we skip type because meta is a step too far for now
        return obj
    if isBuiltIn(type(obj)):
        rolable = builtInProxy(obj)
    else:
        rolable = obj
    if realType(obj) in (tuple, int, str):
        return rolable
    __rolables[obj] = rolable
    __rolables[rolable] = rolable
    return rolable
        
def useRoles(function):
    roles = getCallerRoles()
    print('roles:', roles)
    for rolable in roles:
        if rolable.toTransformFunction():
            print(rolable)
            cls = rolable.superclass
            function = transformFunction(function, cls, rolable)
    return function

