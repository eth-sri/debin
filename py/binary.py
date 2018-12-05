import os
import json
import ctypes
import subprocess
import requests

from elfs.sections import Sections
from elfs.debuginfo import DebugInfo
from elfs.tables import StringTable, SymbolTable, DebugLoc
from elfs.insnmap import InsnMap
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import set_global_machine_arch

from bap.others import Prog

from elements.function import Functions
from elements.offsets import Offset
from elements.regs import RegBase, Reg
from elements.offsets import IndirectOffset

from common import utils
from common.timer import TIMER
from common.stats import Stats
from common.constants import FUN_ARG, LOC_VAR, UNKNOWN_LABEL, GIV_REGS
from common.constants import ENUM_DW_FORM_exprloc, ENUM_DW_TAG, ENUM_DW_AT, ENUM_DW_FORM
from common.constants import ENUM_ABBREV_CODE, ENUM_DW_CHILDREN, ENUM_DW_AT_language
from common.constants import POINTER, ENUM, ARRAY, UNION, STRUCT, VOID
from common.constants import SHORT, UNSIGNED_SHORT, CHAR, UNSIGNED_CHAR, LONG_LONG
from common.constants import UNSIGNED_LONG_LONG, LONG, UNSIGNED_LONG
from common.constants import INT, UNSIGNED_INT, BOOL, MAX_UPPER_BOUND
from common.constants import SYMTAB, TTYPES, TEXT

from depgraph.edges import Edges
from depgraph.nodes import Nodes
from depgraph.factors import Factors
from depgraph.constraints import Constraints

from c.types import Types
from c.variables import make_variables

from collections import OrderedDict


class Binary:
    def __init__(self, config, elffile, debug_elffile=None):
        self.config = config
        self.name = self.config.BINARY_NAME
        self.path = self.config.BINARY_PATH
        self.elffile = ELFFile(elffile)
        self.entry_point = self.elffile.header['e_entry'] if 'e_entry' in self.elffile.header else None
        self.binary_type = self.elffile.header['e_type'] if 'e_type' in self.elffile.header else None
        self.init_pc = None
        self.fini_pc = None

        self.insns = dict()
        self.flags = dict()
        self.giv_regs = dict()
        self.giv_offsets = dict()
        self.int_consts = dict()
        self.string_consts = dict()
        self.code_offsets = dict()
        self.switch_tables = dict()
        self.virtual_elms = dict()
        self.temp_offsets = dict()
        self.node_types = dict()
        self.othervar_nodes = dict()
        self.size_nodes = dict()
        self.op_nodes = dict()
        self.unknown_node = None

        self.direct_offsets = dict()

        self.predicted = set()
        self.types = dict()

        set_global_machine_arch(self.elffile.get_machine_arch())
        utils.set_global_machine_arch(self.elffile.get_machine_arch(), self)

        self.sections = Sections(binary=self)

        if self.config.BAP_FILE_PATH == '' or not os.path.exists(self.config.BAP_FILE_PATH):
            if self.config.BYTEWEIGHT_SIGS_PATH == '':
                if self.sections.has_sec(SYMTAB):
                    bap_result = subprocess.getoutput('bap {} --pass=loc --symbolizer=objdump --rooter=internal'.format(self.path))
                else:
                    bap_result = subprocess.getoutput('bap {} --pass=loc --symbolizer=objdump'.format(self.path))
            else:
                bap_result = subprocess.getoutput('bap {} --pass=loc --symbolizer=objdump --byteweight-sigs={}'.format(self.path, self.config.BYTEWEIGHT_SIGS_PATH))
            bap_json = json.loads(bap_result)
        else:
            bap_json = json.load(open(self.config.BAP_FILE_PATH))

        self.insn_map = InsnMap(**bap_json)
        self.bap = Prog(**bap_json, binary=self, has_symtab=self.sections.has_sec(SYMTAB))

        self.functions = Functions(bap=self.bap.subs, binary=self)
        self.functions.initialize()
        self.low_pc = self.functions.low_pc
        self.high_pc = self.functions.high_pc
        self.sections.init_dynsym_offsets()

        self.nodes = Nodes(binary=self)
        self.edges = Edges(binary=self)
        self.factors = Factors(binary=self)
        self.constraints = Constraints(binary=self)

        self.string_table = None
        self.symbol_table = None
        self.debug_loc = None

        if self.config.MODE == self.config.TRAIN:
            self.stats = Stats(self)
            self.debug_info = DebugInfo(binary=self, debug_elffile=debug_elffile)
            self.debug_info.binary_train_info()

        self.nodes.initialize()
        self.edges.initialize()

    def dump_debug(self):
        with open(self.config.DEBUG_PATH, 'w') as w:
            for f in self.functions.functions:
                w.write('function {}\n'.format(repr(f)))
                w.write('function {}\n'.format(str(f)))
                for blk_tid in sorted(f.blks.keys()):
                    blk = f.blks[blk_tid]
                    w.write('blk {}\n'.format(blk_tid))
                    for stmt in blk.stmts:
                        pc = format(stmt.pc, '02x') if stmt.pc is not None else None
                        w.write('stmt: {} {}\n'.format(pc, stmt.insn))
                        w.write('raw: {}\n'.format(repr(stmt)))
                        w.write('debug: {}\n'.format(str(stmt)))
                    w.write('\n')
                w.write('\n')

    def dump_stat(self):
        self.stats.stat()
        self.stats.dump()

    def dump_corrects(self):
        self.stats.stat()
        self.stats.dump_corrects()

    def dump_errors(self):
        self.stats.stat()
        self.stats.dump_errors()

    def dump_edges(self):
        self.edges.dump()

    def to_json(self, clear=False):
        assign = self.nodes.to_json(clear)
        query = self.edges.to_json()
        query += self.factors.to_json()
        query += self.constraints.to_json()
        return OrderedDict([('assign', assign), ('query', query)])

    def dump_graph(self):
        j = json.dumps(self.to_json())
        with open(self.config.GRAPH_PATH, 'w') as w:
            w.write(j)
            w.write('\n')

    def dump_predicted(self):
        predicted = sorted(list(self.predicted))
        with open(self.config.PREDICTEDS_PATH, 'w') as w:
            w.write('\n'.join(predicted))

    def set_test_result_from_path(self, result_path):
        with open(result_path, 'r') as result:
            j = json.load(result)
            self.set_test_result(j)

    def set_test_result_from_server(self, clear=False):
        utils.write_progress('Making Prediction...', self)
        url = self.config.N2P_SERVER_URL
        params = self.to_json(clear)
        data = {
            'method': 'infer',
            'params': params,
            'jsonrpc': '2.0',
            'id': 0,
        }
        response = requests.post(url, data=json.dumps(data)).json()
        self.set_test_result(response['result'])

    def set_test_result(self, j):
        nodes_json = j['assign'] if 'assign' in j else j
        # nodes_json = j['result'] if 'result' in j else j

        for node_json in nodes_json:
            if 'inf' in node_json:
                node = self.nodes.nodes[node_json['v']]
                node.test_name = node_json['inf']
                # if node.test_name not in TTYPES and node.test_name != UNKNOWN_LABEL:
                #     self.predicted.add(node.test_name)

        if self.config.MODE == self.config.TRAIN \
                and self.config.STAT_PATH != '':
            self.stats.stat_result(nodes_json)

    def get_features(self):
        reg_x = []
        reg_y = []
        off_x = []
        off_y = []

        for node in self.nodes.nodes.values():
            if isinstance(node, Reg) and node.function.init_run:
                reg_x.append(list(node.features))
                if node.train_name != UNKNOWN_LABEL:
                    reg_y.append(1)
                else:
                    reg_y.append(0)
            elif isinstance(node, IndirectOffset) and node.function.init_run:
                off_x.append(list(node.features))
                if node.train_name != UNKNOWN_LABEL:
                    off_y.append(1)
                else:
                    off_y.append(0)

        return reg_x, reg_y, off_x, off_y

    def get_debug_abbrev(self):
        bs = bytearray()

        bs.append(ENUM_ABBREV_CODE['COMPILE_UNIT'])
        bs.append(ENUM_DW_TAG['DW_TAG_compile_unit'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_yes'])
        bs.append(ENUM_DW_AT['DW_AT_language'])
        bs.append(ENUM_DW_FORM['DW_FORM_data1'])
        bs.append(ENUM_DW_AT['DW_AT_low_pc'])
        bs.append(ENUM_DW_FORM['DW_FORM_addr'])
        bs.append(ENUM_DW_AT['DW_AT_high_pc'])
        bs.append(ENUM_DW_FORM['DW_FORM_addr'])
        bs.append(0x00)
        bs.append(0x00)

        bs.append(ENUM_ABBREV_CODE['SUBPROGRAM'])
        bs.append(ENUM_DW_TAG['DW_TAG_subprogram'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_yes'])
        bs.append(ENUM_DW_AT['DW_AT_name'])
        bs.append(ENUM_DW_FORM['DW_FORM_string'])
        bs.append(ENUM_DW_AT['DW_AT_type'])
        bs.append(ENUM_DW_FORM['DW_FORM_ref4'])
        bs.append(ENUM_DW_AT['DW_AT_low_pc'])
        bs.append(ENUM_DW_FORM['DW_FORM_addr'])
        bs.append(ENUM_DW_AT['DW_AT_high_pc'])
        if self.config.ADDRESS_BYTE_SIZE == 4:
            bs.append(ENUM_DW_FORM['DW_FORM_data4'])
        elif self.config.ADDRESS_BYTE_SIZE == 8:
            bs.append(ENUM_DW_FORM['DW_FORM_data8'])
        bs.append(0x00)
        bs.append(0x00)

        bs.append(ENUM_ABBREV_CODE['SUBPROGRAM_VOID'])
        bs.append(ENUM_DW_TAG['DW_TAG_subprogram'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_yes'])
        bs.append(ENUM_DW_AT['DW_AT_name'])
        bs.append(ENUM_DW_FORM['DW_FORM_string'])
        bs.append(ENUM_DW_AT['DW_AT_low_pc'])
        bs.append(ENUM_DW_FORM['DW_FORM_addr'])
        bs.append(ENUM_DW_AT['DW_AT_high_pc'])
        if self.config.ADDRESS_BYTE_SIZE == 4:
            bs.append(ENUM_DW_FORM['DW_FORM_data4'])
        elif self.config.ADDRESS_BYTE_SIZE == 8:
            bs.append(ENUM_DW_FORM['DW_FORM_data8'])
        bs.append(0x00)
        bs.append(0x00)

        bs.append(ENUM_ABBREV_CODE['VARIABLE'])
        bs.append(ENUM_DW_TAG['DW_TAG_variable'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_no'])
        bs.append(ENUM_DW_AT['DW_AT_name'])
        bs.append(ENUM_DW_FORM['DW_FORM_string'])
        bs.append(ENUM_DW_AT['DW_AT_location'])
        bs.append(ENUM_DW_FORM['DW_FORM_exprloc'])
        bs.append(ENUM_DW_AT['DW_AT_type'])
        bs.append(ENUM_DW_FORM['DW_FORM_ref4'])
        bs.append(0x00)
        bs.append(0x00)

        bs.append(ENUM_ABBREV_CODE['LOC_VARIABLE'])
        bs.append(ENUM_DW_TAG['DW_TAG_variable'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_no'])
        bs.append(ENUM_DW_AT['DW_AT_name'])
        bs.append(ENUM_DW_FORM['DW_FORM_string'])
        bs.append(ENUM_DW_AT['DW_AT_location'])
        bs.append(ENUM_DW_FORM['DW_FORM_sec_offset'])
        bs.append(ENUM_DW_AT['DW_AT_type'])
        bs.append(ENUM_DW_FORM['DW_FORM_ref4'])
        bs.append(0x00)
        bs.append(0x00)

        bs.append(ENUM_ABBREV_CODE['FUN_ARG'])
        bs.append(ENUM_DW_TAG['DW_TAG_formal_parameter'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_no'])
        bs.append(ENUM_DW_AT['DW_AT_name'])
        bs.append(ENUM_DW_FORM['DW_FORM_string'])
        bs.append(ENUM_DW_AT['DW_AT_location'])
        bs.append(ENUM_DW_FORM['DW_FORM_exprloc'])
        bs.append(ENUM_DW_AT['DW_AT_type'])
        bs.append(ENUM_DW_FORM['DW_FORM_ref4'])
        bs.append(0x00)
        bs.append(0x00)

        bs.append(ENUM_ABBREV_CODE['LOC_FUN_ARG'])
        bs.append(ENUM_DW_TAG['DW_TAG_formal_parameter'])
        bs.append(ENUM_DW_CHILDREN['DW_CHILDREN_no'])
        bs.append(ENUM_DW_AT['DW_AT_name'])
        bs.append(ENUM_DW_FORM['DW_FORM_string'])
        bs.append(ENUM_DW_AT['DW_AT_location'])
        bs.append(ENUM_DW_FORM['DW_FORM_sec_offset'])
        bs.append(ENUM_DW_AT['DW_AT_type'])
        bs.append(ENUM_DW_FORM['DW_FORM_ref4'])
        bs.append(0x00)
        bs.append(0x00)

        bs += self.types.debug_abbrev()

        bs.append(0x00)

        return bs

    def get_debug_info(self):
        bs = bytearray()

        # version
        bs.append(0x02)
        bs.append(0x00)

        # abbrev offset
        bs.append(0x00)
        bs.append(0x00)
        bs.append(0x00)
        bs.append(0x00)

        # pointer size
        bs.append(int(self.config.ADDRESS_BYTE_SIZE))

        # compile unit
        bs.append(ENUM_ABBREV_CODE['COMPILE_UNIT'])
        # DW_AT_language
        bs.append(ENUM_DW_AT_language['DW_LANG_C89'])

        bs += utils.encode_address(self.sections.sections[TEXT].addr, self)
        bs += utils.encode_address(self.sections.sections[TEXT].end_addr, self)

        self.string_table = StringTable(binary=self)
        self.symbol_table = SymbolTable(binary=self)
        self.debug_loc = DebugLoc(binary=self)
        self.types = Types(binary=self, offset=len(bs))

        bs_rest = bytearray()

        for off in sorted(self.direct_offsets.keys()):
            direct_offset = self.direct_offsets[off]
            if direct_offset.test_name is not None \
                    and direct_offset.test_name != UNKNOWN_LABEL:
                bs_rest += direct_offset.debug_info()

        for low_pc in sorted(self.functions.functions_by_lowpc.keys()):
            f = self.functions.functions_by_lowpc[low_pc]
            if f.is_run_init \
                    and f.test_name is not None \
                    and f.test_name != UNKNOWN_LABEL:
                bs_rest += f.debug_info()

        bs_rest.append(0x00)

        bs = bs + self.types.content + bs_rest

        length = len(bs)
        bs = length.to_bytes(4, byteorder='little') + bs
        return bs

    def modify_elf(self):
        utils.write_progress('Preparing Output...', self)
        modify_elf = ctypes.cdll.LoadLibrary(self.config.MODIFY_ELF_LIB_PATH).modify_elf
        modify_elf.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_char_p
        ]

        info = self.get_debug_info()
        abbrev = self.get_debug_abbrev()
        loc = self.debug_loc.content
        self.symbol_table.debug_info()
        strtab = self.string_table.content
        symtab = self.symbol_table.content
        symtab_info = self.symbol_table.num_entries

        modify_elf(
            self.config.BINARY_PATH.encode('ascii'),
            self.config.OUTPUT_BINARY_PATH.encode('ascii'),
            len(info),
            bytes(info),
            len(abbrev),
            bytes(abbrev),
            len(loc),
            bytes(loc),
            len(strtab),
            bytes(strtab),
            0 if self.sections.has_sec(SYMTAB) else len(symtab),
            self.config.ADDRESS_BYTE_SIZE * 2 + 8,
            symtab_info,
            bytes(symtab)
        )
        utils.write_progress('Output Prepared...', self)
