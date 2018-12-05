import bap
from common.utils import adapt_int_width


def build_exp(**kwargs):
    t = kwargs['t']
    if t == 'Load':
        return LoadExp(**kwargs)
    elif t == 'Store':
        return StoreExp(**kwargs)
    elif t == 'BinOp':
        return BinOpExp(**kwargs)
    elif t == 'UnOp':
        return UnOpExp(**kwargs)
    elif t == 'Int':
        return IntExp(**kwargs)
    elif t == 'Cast':
        return CastExp(**kwargs)
    elif t == 'Let':
        return LetExp(**kwargs)
    elif t == 'Unknown':
        return UnknownExp(**kwargs)
    elif t == 'Ite':
        return IteExp(**kwargs)
    elif t == 'Extract':
        return ExtractExp(**kwargs)
    elif t == 'Concat':
        return ConcatExp(**kwargs)
    elif t == 'Var':
        return bap.vars.build_var(**kwargs)


class Exp:
    def __init__(self, *args, **kwargs):
        self.t = kwargs['t']

    def __repr__(self):
        return 'Exp'

    def __str__(self):
        return repr(self)


class LoadExp(Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.addr = build_exp(**kwargs['addr']) if isinstance(kwargs['addr'], dict) else kwargs['addr']
        self.endian = kwargs['endian']
        self.size = kwargs['size']

    def __repr__(self):
        return '(Load [{}])'.format(repr(self.addr))

    def __str__(self):
        return '(Load [{}])'.format(str(self.addr))


class StoreExp(Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.addr = build_exp(**kwargs['addr']) if isinstance(kwargs['addr'], dict) else kwargs['addr']
        self.exp = build_exp(**kwargs['exp']) if isinstance(kwargs['exp'], dict) else kwargs['exp']
        self.endian = kwargs['endian']
        self.size = kwargs['size']

    def __repr__(self):
        return '(Store [{}] {})'.format(repr(self.addr), repr(self.exp))

    def __str__(self):
        return '(Store [{}] {})'.format(str(self.addr), str(self.exp))


class BinOpExp(Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.op = kwargs['op']
        self.e1 = build_exp(**kwargs['e1']) if isinstance(kwargs['e1'], dict) else kwargs['e1']
        self.e2 = build_exp(**kwargs['e2']) if isinstance(kwargs['e2'], dict) else kwargs['e2']

        if isinstance(self.e1, IntExp):
            self.e1, self.e2 = self.e2, self.e1

    def __repr__(self):
        return '({} {} {})'.format(self.op, repr(self.e1), repr(self.e2))

    def __str__(self):
        return '({} {} {})'.format(self.op, str(self.e1), str(self.e2))

    def str_noindex(self):
        return '({} {} {})'.format(self.e1.str_noindex(), self.op, self.e2.str_noindex())


class UnOpExp(Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.op = kwargs['op']
        self.e = build_exp(**kwargs['e']) if isinstance(kwargs['e'], dict) else kwargs['e']

    def __repr__(self):
        return '({} {})'.format(self.op, repr(self.e))

    def __str__(self):
        return '({} {})'.format(self.op, str(self.e))


class CastExp(Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kind = kwargs['kind']
        self.size = kwargs['size']
        self.e = build_exp(**kwargs['e']) if isinstance(kwargs['e'], dict) else kwargs['e']

    def __repr__(self):
        return '({} {} {})'.format(self.kind, self.size, repr(self.e))

    def __str__(self):
        return '({} {} {})'.format(self.kind, self.size, str(self.e))

    def str_noindex(self):
        return self.e.str_noindex()


class IntExp(Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.value = adapt_int_width(kwargs['value'], kwargs['width'])
        self.width = kwargs['width']

    def __repr__(self):
        return '({} {})'.format(self.width, self.value)

    def __str__(self):
        return repr(self)

    def str_noindex(self):
        return str(self.value)


class LetExp(Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.v = bap.vars.build_var(**kwargs['v']) if isinstance(kwargs['v'], dict) else kwargs['v']
        self.head = build_exp(**kwargs['head']) if isinstance(kwargs['head'], dict) else kwargs['head']
        self.body = build_exp(**kwargs['body']) if isinstance(kwargs['body'], dict) else kwargs['body']

    def __repr__(self):
        return '(Let {} {} {})'.format(repr(self.v), repr(self.head), repr(self.body))

    def __str__(self):
        return '(Let {} {} {})'.format(str(self.v), str(self.head), str(self.body))


class UnknownExp(Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.msg = kwargs['msg']

    def __repr__(self):
        return '(Unknown {})'.format(self.msg)

    def __str__(self):
        return '(Unknown {})'.format(self.msg)


class IteExp(Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cond = build_exp(**kwargs['cond']) if isinstance(kwargs['cond'], dict) else kwargs['cond']
        self.yes = build_exp(**kwargs['yes']) if isinstance(kwargs['yes'], dict) else kwargs['yes']
        self.no = build_exp(**kwargs['no']) if isinstance(kwargs['no'], dict) else kwargs['no']

    def __repr__(self):
        return '(Ite {} {} {})'.format(repr(self.cond), repr(self.yes), repr(self.no))

    def __str__(self):
        return '(Ite {} {} {})'.format(str(self.cond), str(self.yes), str(self.no))


class ExtractExp(Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hi = kwargs['hi']
        self.lo = kwargs['lo']
        self.e = build_exp(**kwargs['e']) if isinstance(kwargs['e'], dict) else kwargs['e']

    def __repr__(self):
        return '(Extract {} {} {})'.format(self.hi, self.lo, repr(self.e))

    def __str__(self):
        return '(Extract {} {} {})'.format(self.hi, self.lo, str(self.e))


class ConcatExp(Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.e1 = build_exp(**kwargs['e1']) if isinstance(kwargs['e1'], dict) else kwargs['e1']
        self.e2 = build_exp(**kwargs['e2']) if isinstance(kwargs['e2'], dict) else kwargs['e2']

    def __repr__(self):
        return '(Concat {} {})'.format(repr(self.e1), repr(self.e2))

    def __str__(self):
        return '(Concat {} {})'.format(str(self.e1), str(self.e2))
