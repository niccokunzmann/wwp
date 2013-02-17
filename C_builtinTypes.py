from relative import roleOf, useRoles

@roleOf(int)
class NaturalNumber:
    @property
    def successor(self):
        return self + 1

@useRoles
def test():
    # this is possible if we recompile the code objects
    i = 1
    assert i.successor == 2

if __name__ == '__main__':
    test()

