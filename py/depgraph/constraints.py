from collections import OrderedDict


class Constraints:
    def __init__(self, *args, **kwargs):
        self.binary = kwargs['binary']
        self.constraints = set()
        self.constraints.add(frozenset(self.binary.functions.functions))

    def to_json(self):
        query = []
        for constraint in self.constraints:
            constraint = list(map(lambda n: n.id, constraint))
            query.append(OrderedDict([('cn', '!='), ('n', constraint)]))
        return query
