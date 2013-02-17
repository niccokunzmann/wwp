
import sys
sys.setrecursionlimit(100)
from relative import roleOf, useRoles

@roleOf(int)
class NaturalNumber:
    @property
    def successor(self):
        print('!!!!!!!!!!!!!!', type(self))
        return 1 + self

@roleOf(tuple)
@roleOf(list)
class MyList:
    @property
    def first(self):
        return self[0]

@useRoles
def test():
    # this is possible if we recompile the code objects
    i = 1
    print(type(i))
    assert i.successor == 2
    assert i.successor.successor == 3
    # check for identity
    t = (3,)
    assert t.first == 3
    l = list()
    l.append(3)
    assert l.first == 3
    assert l.first == 2 + 1

# todo: test converting function arguments
# set code object of the function to locally created one

if __name__ == '__main__':

    test()

