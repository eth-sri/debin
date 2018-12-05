import bap


def build_var(**kwargs):
    k = kwargs['kind']
    if k == 'Virtual':
        return VirtualVar(**kwargs)
    elif k == 'Reg':
        return RegVar(**kwargs)
    elif k == 'Flag':
        return FlagVar(**kwargs)
    elif k == 'Mem':
        return MemVar(**kwargs)
    elif k == 'Other':
        return OtherVar(**kwargs)


class Var(bap.exps.Exp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kind = kwargs['kind']

    def __repr__(self):
        return 'Var'

    def __str__(self):
        return repr(self)


def format_virtual(name_index):
    name = ''
    index = ''
    for c in name_index:
        if c.isalpha() or c == '_':
            name += c
        else:
            index += c
    return name, int(index)


class VirtualVar(Var):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name, self.index = format_virtual(kwargs['name'])

    def __repr__(self):
        return '{}.{}'.format(self.name, self.index)

    def __str__(self):
        return repr(self)
    

class RegVar(Var):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = kwargs['name']
        self.index = kwargs['index']

    def __repr__(self):
        return '{}.{}'.format(self.name, self.index)

    def __str__(self):
        return repr(self)
    
    def str_noindex(self):
        return self.name


class FlagVar(Var):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = kwargs['name']
        self.index = kwargs['index']

    def __repr__(self):
        return '{}.{}'.format(self.name, self.index)

    def __str__(self):
        return repr(self)


class MemVar(Var):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = kwargs['name']
        self.index = kwargs['index']

    def __repr__(self):
        return '{}.{}'.format(self.name, self.index)

    def __str__(self):
        return repr(self)


class OtherVar(Var):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = kwargs['name']
        self.index = kwargs['index']

    def __repr__(self):
        return '{}.{}'.format(self.name, self.index)

    def __str__(self):
        return repr(self)

    def str_noindex(self):
        return self.name
