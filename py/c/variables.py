from common import utils
from common.constants import FUN_ARG, LOC_VAR, ENUM_ABBREV_CODE, UNKNOWN_LABEL
from common.constants import VOID, INT, TTYPES

from collections import Counter

from elements.regs import Reg
from elements.offsets import IndirectOffset


def make_variables(locs, binary):
    variables = dict()
    for loc in locs:
        if loc.test_name is not None \
                and loc.test_name != UNKNOWN_LABEL \
                and loc.n2p_type == binary.config.INF \
                and len(loc.pcs) > 0:
            key = (loc.test_name, loc.ttype.test_name)
            if key not in variables:
                variables[key] = Variable(binary=loc.binary, name=loc.test_name, ttype=loc.ttype.test_name)
            variables[key].add_loc(loc)
    return variables.values()


class Variable:

    def __init__(self, *args, **kwargs):
        self.locs = []
        self.binary = kwargs['binary']
        self.name = kwargs['name']
        self.ttype = kwargs['ttype']
        self.low_pc = None
        self.high_pc = None
        self.var_type = LOC_VAR
        self.fun_arg_loc = None

    def add_loc(self, loc):
        self.locs.append(loc)
        self.low_pc = min(self.low_pc, loc.low_pc) if self.low_pc is not None else loc.low_pc
        self.high_pc = max(self.high_pc, loc.high_pc) if self.high_pc is not None else loc.high_pc
        if loc.var_type == FUN_ARG:
            self.var_type = FUN_ARG
            if isinstance(loc, Reg):
                self.fun_arg_loc = (loc.base_register, -1)
            elif isinstance(loc, IndirectOffset):
                self.fun_arg_loc = (loc.base_pointer, loc.offset)

    def debug_info(self):
        if len(self.locs) == 1 \
                and isinstance(self.locs[0], IndirectOffset):
            loc = self.locs[0]
            return loc.debug_info()
        else:
            bs = bytearray()

            if self.var_type == FUN_ARG:
                bs.append(ENUM_ABBREV_CODE['LOC_FUN_ARG'])
            else:
                bs.append(ENUM_ABBREV_CODE['LOC_VARIABLE'])

            # name
            bs.extend(map(ord, self.name))
            bs.append(0x00)

            if self.name not in TTYPES and self.name != UNKNOWN_LABEL:
                self.binary.predicted.add(self.name)

            bs += utils.encode_kbytes(len(self.binary.debug_loc.content), 4)
            self.binary.debug_loc.add_locs(self.locs)

            # ttypes = Counter(map(lambda l: l.ttype.test_name, self.locs))
            # ttype = max(ttypes, key=ttypes.get)

            if self.ttype is None \
                    or self.ttype in (UNKNOWN_LABEL, VOID) \
                    or self.ttype not in TTYPES:
                bs += utils.encode_kbytes(self.binary.types.get_offset(INT), 4)
            else:
                bs += utils.encode_kbytes(self.binary.types.get_offset(self.ttype), 4)

            return bs

    def __str__(self):
        repr(self)

    def __repr__(self):
        return '[{}]'.format(', '.join(map(repr, self.locs)))