import re
from common.idgen import IDGEN


class Node:
    def __init__(self, *args, **kwargs):
        self.id = IDGEN.gen()

    def __hash__(self):
        return self.id

    def __eq__(self, other):
        return self.id == other.id


class GivElm(Node):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary = kwargs['binary']

    def __repr__(self):
        return 'GivElm'

    def __str__(self):
        return repr(self)

    def stat(self):
        GivElm.total += 1


class IntConst(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.value = kwargs['value']
        self.width = kwargs['width']
        self.name = '@INT_' + str(self.value)

    def __repr__(self):
        return '({} {})'.format(format(self.width), self.value)

    def __str__(self):
        return repr(self)

    def str_noindex(self):
        return repr(self)

    def stat(self):
        super().stat()
        IntConst.total += 1


class StringConst(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.offset = kwargs['offset']
        self.value = kwargs['value']
        self.value = self.value.replace('\n', '\\n')
        self.value = self.value.replace('\t', '\\t')
        self.value = re.sub(' +', ' ', self.value)
        self.access = kwargs['access']
        self.name = '@STR_' + str(self.value)

    def __repr__(self):
        return '({} {} \'{}\')'.format(format(self.offset, '02x'), repr(self.access), self.value)

    def __str__(self):
        return '(\'{}\')'.format(self.value)

    def stat(self):
        super().stat()
        StringConst.total += 1


class SwitchTable(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.offset = kwargs['offset']
        self.locs = kwargs['locs']
        self.access = kwargs['access']

    def __repr__(self):
        return '(SwitchTable {})'.format(format(self.offset, '02x'))

    def __str__(self):
        return repr(self)

    def stat(self):
        super().stat()
        SwitchTable.total += 1


class Flag(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.base_flag = kwargs['base_flag']
        self.index = kwargs['index']
        self.name = '{}:{}'.format(self.base_flag, self.index)

    def __repr__(self):
        return '{}.{}'.format(self.base_flag, self.index)

    def __str__(self):
        return repr(self)
    
    def str_noindex(self):
        return self.base_flag

    def stat(self):
        super().stat()
        Flag.total += 1


class Insn(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = kwargs['name']

    def __repr__(self):
        return self.name

    def __str__(self):
        return repr(self)

    def stat(self):
        super().stat()
        Insn.total += 1


class CodeOffset(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.offset = kwargs['offset']
        self.target = kwargs['target']
        self.access = kwargs['access']

    def __repr__(self):
        return '(CodeOffset {} {})'.format(format(self.offset, '02x'), repr(self.target))

    def __str__(self):
        return '(CodeOffset {})'.format(str(self.target))

    def str_noindex(self):
        return 'CodeOffset'

    def stat(self):
        super().stat()
        CodeOffset.total += 1


class VirtualElm(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = kwargs['name']

    def __repr__(self):
        return self.name

    def __str__(self):
        return repr(self)

    def stat(self):
        super().stat()
        VirtualElm.total += 1


class NodeType(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = kwargs['name']

    def __repr__(self):
        return '(NodeType {})'.format(self.name)

    def __str__(self):
        return repr(self)

    def stat(self):
        super().stat()
        NodeType.total += 1


class OpNode(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = kwargs['name']

    def __repr__(self):
        return self.name

    def __str__(self):
        return repr(self) 

    def stat(self):
        super().stat()
        OpNode.total += 1


class OtherVarNode(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = kwargs['name']

    def __repr__(self):
        return self.name

    def __str__(self):
        return repr(self)

    def str_noindex(self):
        return self.name

    def stat(self):
        super().stat()
        OtherVarNode.total += 1


class SizeNode(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.size = kwargs['size']

    def __repr__(self):
        return str(self.size)

    def __str__(self):
        return repr(self)

    def stat(self):
        super().stat()
        SizeNode.total += 1


class UnknownNode(GivElm):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return 'Unknown'

    def __str__(self):
        return repr(self)

    def str_noindex(self):
        return 'Unknown'

    def stat(self):
        super().stat()
        UnknownNode.total += 1


class VirtualExp:
    def __init__(self, *args, **kwargs):
        self.name = kwargs['name']
        self.index = kwargs['index']
        self.exp = kwargs['exp']
        self.elm = kwargs['elm']
        self.blk = kwargs['blk']
        self.pc = kwargs['pc']

    def __repr__(self):
        if isinstance(self.exp, list):
            return '({}{} {})'.format(self.name, self.index, ', '.format(map(repr, self.exp)))
        else:
            return '({}{} {})'.format(self.name, self.index, repr(self.exp))

    def __str__(self):
        if isinstance(self.exp, list):
            return '({}{} {})'.format(self.name, self.index, ', '.format(map(str, self.exp)))
        else:
            return '({}{} {})'.format(self.name, self.index, str(self.exp))

    def str_noindex(self):
        if isinstance(self.exp, list):
            return ', '.join(map(lambda e: e.str_noindex(), self.exp))
        else:
            return self.exp.str_noindex()
