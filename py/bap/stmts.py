from bap.exps import build_exp
from bap.vars import build_var
from bap.exps import IntExp
from elements.givs import IntConst


def build_stmt(**kwargs):
    t = kwargs['t']
    if t == 'Def':
        return DefStmt(**kwargs)
    elif t == 'Phi':
        return PhiStmt(**kwargs)
    elif t == 'Jmp':
        return JmpStmt(**kwargs)


def build_label(**kwargs):
    t = kwargs['t']
    if t == 'Direct':
        return DirectLabel(**kwargs)
    elif t == 'Indirect':
        return IndirectLabel(**kwargs)


def build_jmpkind(**kwargs):
    t = kwargs['t']
    if t == 'Call':
        return CallKind(**kwargs)
    elif t == 'Goto':
        return GotoKind(**kwargs)
    elif t == 'Ret':
        return RetKind(**kwargs)
    elif t == 'Intent':
        return IntentKind(**kwargs)


class Stmt:
    def __init__(self, *args, **kwargs):
        self.t = kwargs['t']
        self.tid = kwargs['tid']
        self.insn = None
        self.pc = None
        if 'insn' in kwargs:
            self.insn = kwargs['insn']
        if 'pc' in kwargs:
            self.pc = kwargs['pc']

    def __repr__(self):
        return 'Stmt'


class DefStmt(Stmt):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lhs = build_var(**kwargs['lhs']) if isinstance(kwargs['lhs'], dict) else kwargs['lhs']
        self.rhs = build_exp(**kwargs['rhs']) if isinstance(kwargs['rhs'], dict) else kwargs['rhs']

    def __repr__(self):
        return '{} = {}'.format(repr(self.lhs), repr(self.rhs))

    def __str__(self):
        return '{} = {}'.format(str(self.lhs), str(self.rhs))


class PhiStmt(Stmt):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lhs = build_var(**kwargs['lhs']) if isinstance(kwargs['lhs'], dict) else kwargs['lhs']
        self.rhs = []
        rhs_exp_set = set()
        for e in kwargs['rhs']:
            if isinstance(e, dict):
                exp = build_exp(**e)
                if repr(exp) not in rhs_exp_set:
                    rhs_exp_set.add(repr(exp))
                    self.rhs.append(exp)
            else:
                self.rhs.append(e)
        self.rhs = list(sorted(self.rhs, key=lambda e: e.index))

    def __repr__(self):
        return '{} = Phi[{}]'.format(repr(self.lhs), ', '.join(map(repr, self.rhs)))

    def __str__(self):
        return '{} = Phi[{}]'.format(str(self.lhs), ', '.join(map(str, self.rhs)))


class JmpStmt(Stmt):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cond = build_exp(**kwargs['cond']) if isinstance(kwargs['cond'], dict) else kwargs['cond']
        self.kind = build_jmpkind(**kwargs['kind']) if isinstance(kwargs['kind'], dict) else kwargs['kind']

    def __repr__(self):
        if (isinstance(self.cond, IntExp) or isinstance(self.cond, IntConst)) and self.cond.value == 1:
            return repr(self.kind)
        else:
            return '{} when {}'.format(repr(self.kind), repr(self.cond))

    def __str__(self):
        if (isinstance(self.cond, IntExp) or isinstance(self.cond, IntConst)) and self.cond.value == 1:
            return str(self.kind)
        else:
            return '{} when {}'.format(str(self.kind), str(self.cond))


class JmpLabel():
    def __init__(self, *args, **kwargs):
        self.t = kwargs['t']

    def __repr__(self):
        return 'JmpLabel'

    def __str__(self):
        return repr(self)


class DirectLabel(JmpLabel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_tid = kwargs['target_tid']

    def __repr__(self):
        return self.target_tid

    def __str__(self):
        return repr(self)


class IndirectLabel(JmpLabel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.exp = build_exp(**kwargs['exp']) if isinstance(kwargs['exp'], dict) else kwargs['exp']

    def __repr__(self):
        return repr(self.exp)

    def __str__(self):
        return str(self.exp)


class JmpKind():
    def __init__(self, *args, **kwargs):
        self.t = kwargs['t']

    def __repr__(self):
        return 'JmpKind'

    def __str__(self):
        return repr(self)


class CallKind(JmpKind):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if 'call' in kwargs:
            self.target = build_label(**kwargs['call']['target'])
            self.rtn = None if kwargs['call']['rtn'] == 'None' else build_label(**kwargs['call']['rtn'])
        else:
            self.target = kwargs['target']
            self.rtn = kwargs['rtn']
        if 'args' in kwargs:
            self.args = kwargs['args']
        else:
            self.args = dict()

    def __repr__(self):
        if self.rtn is None:
            return 'Call {}'.format(repr(self.target))
        else:
            return 'Call {} with return {}'.format(repr(self.target), repr(self.rtn))

    def __str__(self):
        if self.rtn is None:
            return 'Call {}'.format(str(self.target))
        else:
            return 'Call {} with return {}'.format(str(self.target), str(self.rtn))


class GotoKind(JmpKind):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.label = build_label(**kwargs['label']) if isinstance(kwargs['label'], dict) else kwargs['label']

    def __repr__(self):
        return 'Goto {}'.format(repr(self.label))

    def __str__(self):
        return 'Goto {}'.format(str(self.label))


class RetKind(JmpKind):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.label = build_label(**kwargs['label']) if isinstance(kwargs['label'], dict) else kwargs['label']

    def __repr__(self):
        return 'Ret {}'.format(repr(self.label))

    def __str__(self):
        return 'Ret {}'.format(str(self.label))


class IntentKind(JmpKind):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return 'IntentKind'

    def __str__(self):
        return repr(self)
