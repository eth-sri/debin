from depgraph.infos import coarse
from elements.elmfactory import make_node_type
from collections import OrderedDict


class Factors:
    def __init__(self, *args, **kwargs):
        self.binary = kwargs['binary']
        self.factors = set()

    def add_phi_factor(self, nodes):
        if len(nodes) > 1:
            node_type = make_node_type(coarse(nodes[0]), self.binary)
            nodes.append(node_type)
            factors = frozenset(nodes)
            self.factors.add(factors)

    def add_funarg_factor(self, nodes, is_ttype):
        if len(nodes) > 2:
            if is_ttype:
                node_type = make_node_type('FUNC_ARGS_TTYPE', self.binary)
            else:
                node_type = make_node_type('FUNC_ARGS_NAME', self.binary)
            nodes.append(node_type)
            factors = frozenset(nodes)
            self.factors.add(factors)
    
    def add_stmt_factor(self, nodes):
        if len(nodes) > 2:
            factors = frozenset(nodes)
            self.factors.add(factors)

    def to_json(self):
        query = []
        for factor in self.factors:
            factor = list(map(lambda n: n.id, factor))
            query.append(OrderedDict([('group', factor)]))
        return query
