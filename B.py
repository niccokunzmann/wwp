from relative import roleOf
from A import AC, ac

@roleOf(AC)
class BC:

    def __init__(self):
        self.name_count = 0

    def getName(self):
        self.name_count += 1
        return self.name


def test():
    assert ac.name_count == 0
    assert ac.getName() == 'ac'
    assert ac.name_count == 1

if __name__ == '__main__':
    test()
