import elements
from common.constants import UNKNOWN_LABEL, VOID
from elements.givs import Node


class Ttype(Node):
    total = 0
    known = 0
    unknown = 0
    inf = 0
    tp_1p = 0
    fp_1p = 0
    tn_1p = 0
    fn_1p = 0
    correct = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.owner = kwargs['owner']
        self.binary = self.owner.binary
        self.name = self.owner.name + '_type'
        self.train_name = UNKNOWN_LABEL
        self.test_name = UNKNOWN_LABEL

    def __repr__(self):
        return '(Ttype {})'.format(self.name)

    def __str__(self):
        if self.test_name == self.train_name:
            return '(Ttype {})'.format(self.train_name)
        else:
            if self.train_name == UNKNOWN_LABEL:
                return '(Ttype WRONGU {} {})'.format(self.train_name, self.test_name)
            else:
                return '(Ttype WRONGK {} {})'.format(self.train_name, self.test_name)

    def train_info(self, train_name):
        if self.train_name in (UNKNOWN_LABEL, VOID) and train_name != UNKNOWN_LABEL:
            self.train_name = train_name

    def stat(self):
        owner_type = type(self.owner)

        Ttype.total += 1
        owner_type.ttype_total += 1

        if self.train_name != UNKNOWN_LABEL:
            Ttype.known += 1
            owner_type.ttype_known += 1
        else:
            Ttype.unknown += 1
            owner_type.ttype_unknown += 1

        if isinstance(self.owner, elements.regs.Reg) or isinstance(self.owner, elements.offsets.IndirectOffset):
            if self.owner.n2p_type == self.binary.config.INF:
                Ttype.inf += 1
                owner_type.ttype_inf += 1
                if self.train_name == UNKNOWN_LABEL:
                    Ttype.fp_1p += 1
                    owner_type.ttype_fp_1p += 1
                else:
                    Ttype.tp_1p += 1
                    owner_type.ttype_tp_1p += 1
            elif self.owner.n2p_type == self.binary.config.GIV:
                if self.train_name == UNKNOWN_LABEL:
                    Ttype.tn_1p += 1
                    owner_type.ttype_tn_1p += 1
                else:
                    Ttype.fn_1p += 1
                    owner_type.ttype_fn_1p += 1
        elif isinstance(self.owner, elements.offsets.DirectOffset):
            Ttype.inf += 1
            owner_type.ttype_inf += 1
            if self.train_name != UNKNOWN_LABEL:
                Ttype.tp_1p += 1
                owner_type.ttype_tp_1p += 1
                if isinstance(self.owner, elements.offsets.StringArrayOffset):
                    elements.offsets.DirectOffset.ttype_tp_1p += 1
            else:
                Ttype.fp_1p += 1
                owner_type.ttype_fp_1p += 1
                if isinstance(self.owner, elements.offsets.StringArrayOffset):
                    elements.offsets.DirectOffset.ttype_fp_1p += 1
        elif isinstance(self.owner, elements.function.Function):
            Ttype.inf += 1
            owner_type.ttype_inf += 1
            if self.train_name != UNKNOWN_LABEL:
                Ttype.tp_1p += 1
                owner_type.ttype_tp_1p += 1
            else:
                Ttype.fp_1p += 1
                owner_type.ttype_fp_1p += 1
