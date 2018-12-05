class IDGenerator:
    def __init__(self):
        self.id = 0

    def gen(self):
        self.id = self.id + 1
        return self.id


IDGEN = IDGenerator()
