import traceback
import sys
import depgraph
from common import utils
from common.constants import UNKNOWN_LABEL, VOID, ENUM_ABBREV_CODE
from common.constants import X64_FUN_ARG_REGS, ARM_FUN_ARG_REGS, INT, TTYPES
from common.constants import FUN_ARG, LOC_VAR, ENUM_DW_FORM_exprloc
from elements.ttype import Ttype
from elements.givs import Node


class RegBase(Node):
    total = 0
    known = 0
    unknown = 0
    inf = 0
    giv = 0
    tp_1p = 0
    fp_1p = 0
    tn_1p = 0
    fn_1p = 0
    correct = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.base_register = kwargs['base_register']
        self.index = kwargs['index']
        self.name = '{}:R:{}'.format(self.base_register, self.index)
        self.pcs = set()

    def __repr__(self):
        return '(RegBase {}.{})'.format(self.base_register, self.index)

    def __str__(self):
        return repr(self)

    def str_noindex(self):
        return self.base_register

    def stat(self):
        RegBase.total += 1


class GivReg(RegBase):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary = kwargs['binary']

    def __repr__(self):
        return '(GivReg {}.{})'.format(self.base_register, self.index)

    def __str__(self):
        return repr(self)

    def add_pc(self, pc):
        self.pcs.add(pc)

    def str_noindex(self):
        return self.base_register

    def stat(self):
        super().stat()
        GivReg.total += 1
        RegBase.giv += 1


class Reg(RegBase):
    total = 0
    known = 0
    unknown = 0
    inf = 0
    tp_1p = 0
    fp_1p = 0
    tn_1p = 0
    fn_1p = 0
    correct = 0

    ttype_total = 0
    ttype_known = 0
    ttype_unknown = 0
    ttype_inf = 0
    ttype_tp_1p = 0
    ttype_fp_1p = 0
    ttype_tn_1p = 0
    ttype_fn_1p = 0
    ttype_correct = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.function = kwargs['function']
        self.binary = self.function.binary
        self.train_name = UNKNOWN_LABEL
        self.test_name = UNKNOWN_LABEL
        self.low_pc = None
        self.high_pc = None
        self.ttype = Ttype(owner=self)
        self.n2p_type = self.binary.config.INF
        self.features = set()
        self.blks = set()

        if self.binary.config.MACHINE_ARCH == 'x86':
            self.var_type = LOC_VAR
        elif self.binary.config.MACHINE_ARCH == 'x64':
            if self.base_register in X64_FUN_ARG_REGS and self.index == 0:
                self.var_type = FUN_ARG
            else:
                self.var_type = LOC_VAR
        elif self.binary.config.MACHINE_ARCH == 'ARM':
            if self.base_register in ARM_FUN_ARG_REGS and self.index == 0:
                self.var_type = FUN_ARG
            else:
                self.var_type = LOC_VAR

    def __repr__(self):
        return '(Reg {}.{})'.format(self.base_register, self.index)

    def __str__(self):
        if self.test_name == self.train_name:
            return '(Reg {} {})'.format(self.train_name, str(self.ttype))
        else:
            if self.train_name == UNKNOWN_LABEL:
                return '(Reg (WRONGU {} {}) {})'.format(self.train_name, self.test_name, str(self.ttype))
            else:
                return '(Reg (WRONGK {} {}) {})'.format(self.train_name, self.test_name, str(self.ttype))

    def init_features(self):
        coarse = depgraph.infos.coarse
        fine = depgraph.infos.fine

        self.features.add(coarse(self))

        if self.binary.config.MACHINE_ARCH in ('x64', 'ARM') \
                and self.var_type == FUN_ARG:
            self.features.add(fine(self))

        self.features.add('blk[{}][{}]'.format(len(self.blks), coarse(self)))

    def add_pc(self, pc):
        self.pcs.add(pc)
        if self.low_pc is not None:
            self.low_pc = min(pc, self.low_pc)
        else:
            self.low_pc = pc
        if self.high_pc is not None:
            self.high_pc = max(pc, self.high_pc)
        else:
            self.high_pc = pc

    def train_info(self, die, ttype):
        origin = self.binary.debug_info.get_name_origin(die)
        name_attr = origin.attributes.get('DW_AT_name', None)
        if name_attr is not None:
            name = name_attr.value.decode('ascii')
            if self.train_name == UNKNOWN_LABEL:
                self.ttype.train_info(ttype)
                self.train_name = name
            else:
                if self.ttype.train_name in (UNKNOWN_LABEL, VOID) and ttype != UNKNOWN_LABEL:
                    self.ttype.train_info(ttype)
                    self.train_name == name
                else:
                    if self.train_name > name:
                        self.train_name = name
                        self.ttype.train_info(ttype)
        else:
            pass

    def stat(self):
        super().stat()
        Reg.total += 1

        if self.train_name != UNKNOWN_LABEL:
            Reg.known += 1
            RegBase.known += 1
        else:
            Reg.unknown += 1
            RegBase.unknown += 1

        if self.n2p_type == self.binary.config.INF:
            Reg.inf += 1
            RegBase.inf += 1
            if self.train_name == UNKNOWN_LABEL:
                Reg.fp_1p += 1
                RegBase.fp_1p += 1
            else:
                Reg.tp_1p += 1
                RegBase.tp_1p += 1
        elif self.n2p_type == self.binary.config.GIV:
            if self.train_name == UNKNOWN_LABEL:
                Reg.tn_1p += 1
                RegBase.tn_1p += 1
            else:
                Reg.fn_1p += 1
                RegBase.fn_1p += 1

    def debug_info(self):
        bs = bytearray()

        if self.var_type == FUN_ARG:
            bs.append(ENUM_ABBREV_CODE['FUN_ARG'])
        elif self.var_type == LOC_VAR:
            bs.append(ENUM_ABBREV_CODE['VARIABLE'])

        bs.extend(map(ord, self.test_name))
        bs.append(0x0)

        if self.test_name not in TTYPES and self.test_name != UNKNOWN_LABEL:
            self.binary.predicted.add(self.test_name)

        bs.append(0x01)
        bs.append(self.binary.config.REG_MAPPING[self.base_register] + ENUM_DW_FORM_exprloc['DW_OP_reg0'])

        if self.ttype.test_name is None \
                or self.ttype.test_name in (UNKNOWN_LABEL, VOID) \
                or self.ttype.test_name not in TTYPES:
            bs += utils.encode_kbytes(self.binary.types.get_offset(INT), 4)
        else:
            bs += utils.encode_kbytes(self.binary.types.get_offset(self.ttype.test_name), 4)

        return bs
