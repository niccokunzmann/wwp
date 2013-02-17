
import sys
import inspect
import threading
import gc
import types

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
    roles = frame.f_globals.get('__roles__', {})
    return roles    
    

class BaseRolable:

    def __init__(self):
        self.__initializedRoles = []
        print('set', id(self), self)
 
    def changeToRole(self, role):
        self.__class__ = role
        print('change', id(self), self)
        if role not in self.__initializedRoles:
            role.__init__(self)


def rolable(cls):
    class Rolable(BaseRolable, cls):
        def __init__(self, *args, **kw):
            print('self', self, args, kw)
            if cls.__init__ != object.__init__:
                cls.__init__(self, *args, **kw)
            else:
                object.__init__(self)
            BaseRolable.__init__(self)
            
           
        def __getattribute__(self, name):
##            print('getattr1', name)
            roles = getCallerRoles()
##            print('roles', roles, Rolable)
            role = roles.get(Rolable, None)
##            print('role', role is type(self), role, type(self))
            if role is None or role is type(self):
                return super(cls, self).__getattribute__(name)
            self.__class__ = role
            self.changeToRole(role)
            return getattr(self, name)


    Rolable.__module__ = cls.__module__
    Rolable.__name__ = cls.__name__
    return Rolable

__undefined = object()

def roleOf(cls):
    if issubclass(cls, BaseRolable):
        # first this: might have rolable in builtins
        return roleOfRolable(cls)
    elif __builtins.get(cls.__name__, __undefined) is cls:
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
        if rolable in roles:
            raise ValueError('can not have two roles for one object')
        roles[rolable] = Role # cls is the role of base in the modules context
        return role
    return makeRole

builtin_rolables = {}

def roleOfBuiltin(builtinClass):
    # make builtin type rolable
    Builtin = builtin_rolables.get(builtinClass)
    if Builtin is None:
        @rolable
        class Builtin(builtinClass):
            pass
        builtin_rolables[builtinClass] = Builtin
        builtin_rolables[Builtin] = builtinClass
    def makeRole(role):
        raise ModuleTransformationJump('module needs transformation for ' 
                                       'builtin type',
                                       builtinClass,
                                       role)
    return roleOfRolable(Builtin)

def useRoles(function):
    roles = getCallerRoles()
    print('roles:', roles)
    for rolable, role in roles.items():
        if rolable in builtin_rolables:
            cls = builtin_rolables[rolable]
            function = transformFunction(function, cls, rolable)
    return function

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
        print('code:', const, cls, rolable)
        if type(const) == cls:
            const = rolable(const)
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


        
