import traceback
import sys
import depgraph
from common import utils
from common.constants import UNKNOWN_LABEL, VOID, LOC_VAR, FUN_ARG, INT
from common.constants import ENUM_DW_FORM_exprloc, ENUM_ABBREV_CODE, TTYPES
from elements.ttype import Ttype
from elements.givs import Node


class Offset(Node):
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

    def __repr__(self):
        return 'Offset'

    def __str__(self):
        return repr(self)

    def stat(self):
        Offset.total += 1


class GivOffset(Offset):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary = kwargs['binary']
        self.offset = kwargs['offset']
        self.access = kwargs['access']
        self.exp = kwargs['exp']
        self.name = 'GivOffset'

    def __repr__(self):
        return '[GivOffset {}]'.format(repr(self.offset))

    def __str__(self):
        return repr(self)

    def stat(self):
        super().stat()
        GivOffset.total += 1
        Offset.giv += 1


class TempOffset(Offset):
    total = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary = kwargs['binary']
        self.base_pointer = kwargs['base_pointer']
        self.offset = kwargs['offset']
        self.pcs = set()

    def __repr__(self):
        return '[TempOffset {} {}]'.format(self.base_pointer, self.offset)

    def __str__(self):
        return repr(self)

    def add_pc(self, pc):
        self.pcs.add(pc)

    def stat(self):
        super().stat()
        TempOffset.total += 1
        Offset.giv += 1


class DirectOffset(Offset):
    total = 0
    known = 0
    unknown = 0
    inf = 0
    giv = 0
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
        self.binary = kwargs['binary']
        self.offset = kwargs['offset']
        self.access = kwargs['access']
        self.name = '@DO'
        self.is_name_given = False
        self.ttype = Ttype(owner=self)
        self.n2p_type = self.binary.config.INF
        self.train_name = UNKNOWN_LABEL
        self.test_name = UNKNOWN_LABEL
        self.var_type = LOC_VAR

    def __repr__(self):
        return '[DirectOffset {} {}]'.format(format(self.offset, '02x'), repr(self.access))

    def __str__(self):
        if self.test_name == self.train_name or self.is_name_given:
            return '[DirectOffset {} {}]'.format(self.train_name, str(self.ttype))
        else:
            if self.train_name == UNKNOWN_LABEL:
                return '[DirectOffset (WRONGU {} {}) {}]'.format(self.train_name, self.test_name, str(self.ttype))
            else:
                return '[DirectOffset (WRONGK {} {}) {}]'.format(self.train_name, self.test_name, str(self.ttype))

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

        DirectOffset.total += 1
        if self.is_name_given:
            DirectOffset.giv += 1
            Offset.giv += 1
        else:
            DirectOffset.inf += 1
            Offset.inf += 1
            if self.train_name != UNKNOWN_LABEL:
                DirectOffset.known += 1
                Offset.known += 1
                Offset.tp_1p += 1
            else:
                DirectOffset.unknown += 1
                Offset.unknown += 1
                Offset.fp_1p += 1

    def debug_info(self):
        bs = bytearray()
        bs.append(ENUM_ABBREV_CODE['VARIABLE'])

        # name
        bs.extend(map(ord, self.test_name))
        bs.append(0x00)

        if self.test_name not in TTYPES \
                and self.test_name != UNKNOWN_LABEL \
                and self.test_name not in self.binary.sections.symbol_names:
            self.binary.predicted.add(self.test_name)

        bs.append(self.binary.config.ADDRESS_BYTE_SIZE + 1)
        bs.append(ENUM_DW_FORM_exprloc['DW_OP_addr'])
        bs += utils.encode_address(self.offset, self.binary)

        if self.ttype.test_name is None \
                or self.ttype.test_name in (UNKNOWN_LABEL, VOID) \
                or self.ttype.test_name not in TTYPES:
            bs += utils.encode_kbytes(self.binary.types.get_offset(INT), 4)
        else:
            bs += utils.encode_kbytes(self.binary.types.get_offset(self.ttype.test_name), 4)

        return bs


class StringArrayOffset(DirectOffset):
    total = 0
    known = 0
    unknown = 0
    inf = 0
    giv = 0
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
        self.name = '@SA'
        self.strings = kwargs['strings']
        self.access = kwargs['access']

    def __repr__(self):
        return '[StringArray {} ({}) {}]'.format(format(self.offset, '02x'), ', '.join(map(repr, self.strings)), str(self.access))

    def __str__(self):
        if self.test_name == self.train_name:
            return '[StringArray {} {}]'.format(self.train_name, str(self.ttype))
        else:
            if self.train_name == UNKNOWN_LABEL:
                return '[StringArray (WRONGU {} {}) {}]'.format(self.train_name, self.test_name, str(self.ttype))
            else:
                return '[StringArray (WRONGK {} {}) {}]'.format(self.train_name, self.test_name, str(self.ttype))

    def stat(self):
        super().stat()

        StringArrayOffset.total += 1
        if self.is_name_given:
            StringArrayOffset.giv += 1
        else:
            StringArrayOffset.inf += 1
            if self.train_name != UNKNOWN_LABEL:
                StringArrayOffset.known += 1
            else:
                StringArrayOffset.unknown += 1


class IndirectOffset(Offset):
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
        self.base_pointer = kwargs['base_pointer']
        self.offset = kwargs['offset']
        self.index = kwargs['index']
        self.name = '{}:S:{}'.format(self.base_pointer, self.offset)
        self.ttype = Ttype(owner=self)
        self.n2p_type = self.binary.config.INF
        self.train_name = UNKNOWN_LABEL
        self.test_name = UNKNOWN_LABEL
        self.low_pc = None
        self.high_pc = None
        self.pcs = set()
        self.blks = set()
        self.features = set()

        if self.binary.config.MACHINE_ARCH == 'x86':
            if self.base_pointer == 'EBP' and self.offset >= 0:
                self.var_type = FUN_ARG
            else:
                self.var_type = LOC_VAR
        elif self.binary.config.MACHINE_ARCH == 'x64':
            if self.base_pointer == 'RBP' and self.offset >= 0:
                self.var_type = FUN_ARG
            else:
                self.var_type = LOC_VAR
        elif self.binary.config.MACHINE_ARCH == 'ARM':
            self.var_type = LOC_VAR

    def __repr__(self):
        return '[IndirectOffset {} {}]'.format(self.base_pointer, self.offset)

    def __str__(self):
        if self.test_name == self.train_name:
            return '[IndirectOffset {} {}]'.format(self.train_name, str(self.ttype))
        else:
            if self.train_name == UNKNOWN_LABEL:
                return '[IndirectOffset (WRONGU {} {}) {}]'.format(self.train_name, self.test_name, str(self.ttype))
            else:
                return '[IndirectOffset (WRONGK {} {}) {}]'.format(self.train_name, self.test_name, str(self.ttype))

    def init_features(self):
        coarse = depgraph.infos.coarse
        fine = depgraph.infos.fine

        self.features.add(coarse(self))
        self.features.add(fine(self))

        self.features.add('blk[{}][{}]'.format(len(self.blks), coarse(self)))
        self.features.add('blk[{}][{}]'.format(len(self.blks), fine(self)))

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

        IndirectOffset.total += 1
        if self.train_name != UNKNOWN_LABEL:
            IndirectOffset.known += 1
            Offset.known += 1
        else:
            IndirectOffset.unknown += 1
            Offset.unknown += 1

        if self.n2p_type == self.binary.config.INF:
            IndirectOffset.inf += 1
            Offset.inf += 1
            if self.train_name == UNKNOWN_LABEL:
                IndirectOffset.fp_1p += 1
                Offset.fp_1p += 1
            else:
                IndirectOffset.tp_1p += 1
                Offset.tp_1p += 1
        elif self.n2p_type == self.binary.config.GIV:
            if self.train_name == UNKNOWN_LABEL:
                IndirectOffset.tn_1p += 1
                Offset.tn_1p += 1
            else:
                IndirectOffset.fn_1p += 1
                Offset.fn_1p += 1

    def debug_info(self):
        bs = bytearray()

        if self.var_type == FUN_ARG:
            bs.append(ENUM_ABBREV_CODE['FUN_ARG'])
        elif self.var_type == LOC_VAR:
            bs.append(ENUM_ABBREV_CODE['VARIABLE'])

        # name
        bs.extend(map(ord, self.test_name))
        bs.append(0x00)

        if self.test_name not in TTYPES and self.test_name != UNKNOWN_LABEL:
            self.binary.predicted.add(self.test_name)

        loc_expr = bytearray()
        loc_expr.append(self.binary.config.REG_MAPPING[self.base_pointer] +
                        ENUM_DW_FORM_exprloc['DW_OP_breg0'])
        loc_expr += utils.encode_sleb128(self.offset)
        bs += utils.encode_uleb128(len(loc_expr))
        bs += loc_expr

        if self.ttype.test_name is None \
                or self.ttype.test_name in (UNKNOWN_LABEL, VOID) \
                or self.ttype.test_name not in TTYPES:
            bs += utils.encode_kbytes(self.binary.types.get_offset(INT), 4)
        else:
            bs += utils.encode_kbytes(self.binary.types.get_offset(self.ttype.test_name), 4)

        return bs
