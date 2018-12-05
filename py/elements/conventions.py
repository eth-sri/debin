from common.constants import UNKNOWN_LABEL, INIT, FINI, X64_FUN_ARG_REGS, ARM_FUN_ARG_REGS, X86_SOCKETCALL_ARGS

from elements.regs import Reg, RegBase, GivReg
from elements.givs import IntConst, VirtualExp
from elements.elmfactory import mem_addr, make_reg, make_temp_offset
from elements.elmfactory import get_virtual_exp, make_giv_reg

from bap.vars import VirtualVar, RegVar, MemVar
from bap.exps import LoadExp, StoreExp, BinOpExp, IntExp
from bap.stmts import DefStmt, JmpStmt, CallKind, RetKind, DirectLabel, IndirectLabel


def x86_call_args(blk):
    if len(blk.bap.stmts) > 0:
        last_stmt_bap = blk.bap.stmts[-1]
        if isinstance(last_stmt_bap, JmpStmt) \
                and isinstance(last_stmt_bap.kind, CallKind):
            tmp_args = dict()
            call = last_stmt_bap
            for i in range(len(blk.bap.stmts) - 4, -1, -1):
                stmt = blk.bap.stmts[i]
                if isinstance(stmt, DefStmt):
                    lhs = stmt.lhs
                    rhs = stmt.rhs
                    if isinstance(lhs, MemVar) and isinstance(rhs, StoreExp):
                        addr = rhs.addr
                        exp = rhs.exp
                        base_pointer, offset, access = mem_addr(addr, blk, stmt.pc)
                        if base_pointer is not None \
                                and not isinstance(exp, GivReg) \
                                and not isinstance(exp, VirtualVar) \
                                and base_pointer.base_register in ('ESP', 'RSP'):
                            key = (base_pointer.base_register, offset)
                            if key not in tmp_args:
                                tmp_args[key] = (exp, stmt.pc)
            for base_pointer, offset in sorted(tmp_args.keys()):
                key = (base_pointer, offset)
                if offset == 0 or \
                        (base_pointer, offset - blk.binary.config.ADDRESS_BYTE_SIZE) in tmp_args:
                    exp, pc = tmp_args[key]
                    make_temp_offset(base_pointer, offset, blk, pc)
                    call.kind.args[key] = (exp, pc)
                else:
                    break


def x64_call_args(blk):
    if len(blk.bap.stmts) > 0:
        last_stmt_bap = blk.bap.stmts[-1]
        if isinstance(last_stmt_bap, JmpStmt) \
                and isinstance(last_stmt_bap.kind, CallKind):
            call = last_stmt_bap
            for i in range(len(blk.bap.stmts) - 3, -1, -1):
                stmt = blk.bap.stmts[i]
                if isinstance(stmt, DefStmt):
                    lhs = stmt.lhs
                    rhs = stmt.rhs
                    if isinstance(lhs, RegVar) \
                            and lhs.name in X64_FUN_ARG_REGS:
                        key = lhs.name
                        if key not in call.kind.args:
                            make_giv_reg(lhs.name, lhs.index, blk, stmt.pc)
                            call.kind.args[key] = (rhs, stmt.pc)


def arm_call_args(blk):
    if len(blk.bap.stmts) > 0:
        last_stmt_bap = blk.bap.stmts[-1]
        if isinstance(last_stmt_bap, JmpStmt) \
                and isinstance(last_stmt_bap.kind, CallKind):
            call = last_stmt_bap
            for i in range(len(blk.bap.stmts) - 3, -1, -1):
                stmt = blk.bap.stmts[i]
                if isinstance(stmt, DefStmt):
                    lhs = stmt.lhs
                    rhs = stmt.rhs
                    if isinstance(lhs, RegVar) \
                            and lhs.name in ARM_FUN_ARG_REGS:
                        key = lhs.name
                        if key not in call.kind.args:
                            make_giv_reg(lhs.name, lhs.index, blk, stmt.pc)
                            call.kind.args[key] = (rhs, stmt.pc)


def call_args(blk):
    if blk.binary.config.MACHINE_ARCH == 'x86':
        x86_call_args(blk)
    elif blk.binary.config.MACHINE_ARCH == 'x64':
        x64_call_args(blk)
    elif blk.binary.config.MACHINE_ARCH == 'ARM':
        arm_call_args(blk)


def x86_prologue(blk):
    for stmt in blk.bap.stmts:
        if stmt.insn is not None \
                and stmt.insn.startswith('PUSH') \
                and isinstance(stmt.lhs, MemVar) \
                and isinstance(stmt.rhs, StoreExp):
            if isinstance(stmt.rhs.exp, RegVar):
                make_giv_reg(stmt.rhs.exp.name, stmt.rhs.exp.index, blk, stmt.pc)
            elif isinstance(stmt.rhs.exp, VirtualVar) \
                    and isinstance(get_virtual_exp(stmt.rhs.exp, blk).exp, RegVar):
                virtual_exp = get_virtual_exp(stmt.rhs.exp, blk)
                reg = virtual_exp.exp
                make_giv_reg(reg.name, reg.index, blk, stmt.pc)
                make_giv_reg(reg.name, reg.index, blk, virtual_exp.pc)


def x64_prologue(blk):
    x86_prologue(blk)


def arm_prologue(blk):
    for stmt in blk.bap.stmts:
        if stmt.pc is not None \
                and stmt.pc == blk.function.low_pc \
                and isinstance(stmt, DefStmt) \
                and isinstance(stmt.lhs, MemVar) \
                and isinstance(stmt.rhs, StoreExp) \
                and isinstance(stmt.rhs.exp, RegVar):
            base_pointer, offset, access = mem_addr(stmt.rhs.addr, blk, stmt.pc)
            if base_pointer is not None and base_pointer.base_register == 'SP':
                make_temp_offset(base_pointer.base_register, offset, blk, stmt.pc)
                make_giv_reg(stmt.rhs.exp.name, stmt.rhs.exp.index, blk, stmt.pc)
            else:
                break


def prologue(blk):
    if blk.binary.config.MACHINE_ARCH == 'x86':
        x86_prologue(blk)
    elif blk.binary.config.MACHINE_ARCH == 'x64':
        x64_prologue(blk)
    elif blk.binary.config.MACHINE_ARCH == 'ARM':
        arm_prologue(blk)


def x86_epilogue(blk):
    for stmt in blk.bap.stmts:
        if stmt.insn is not None \
                and stmt.insn.startswith('POP') \
                and isinstance(stmt, DefStmt) \
                and isinstance(stmt.lhs, RegVar) \
                and isinstance(stmt.rhs, LoadExp):
            base_pointer, offset, access = mem_addr(stmt.rhs.addr, blk, stmt.pc)
            if base_pointer is not None \
                    and base_pointer.base_register == 'ESP':
                make_temp_offset(base_pointer.base_register, offset, blk, stmt.pc)
                make_giv_reg(stmt.lhs.name, stmt.lhs.index, blk, stmt.pc)


def x64_epilogue(blk):
    for stmt in blk.bap.stmts:
        if stmt.insn is not None \
                and stmt.insn.startswith('POP') \
                and isinstance(stmt, DefStmt) \
                and isinstance(stmt.lhs, RegVar) \
                and isinstance(stmt.rhs, LoadExp):
            base_pointer, offset, access = mem_addr(stmt.rhs.addr, blk, stmt.pc)
            if base_pointer is not None \
                    and base_pointer.base_register == 'RSP':
                make_temp_offset(base_pointer.base_register, offset, blk, stmt.pc)
                make_giv_reg(stmt.lhs.name, stmt.lhs.index, blk, stmt.pc)


def arm_epilogue(blk):
    if len(blk.bap.stmts) > 1:
        last_stmt = blk.bap.stmts[-1]
        if isinstance(last_stmt, JmpStmt) \
                and isinstance(last_stmt.kind, RetKind):
            stmt = blk.bap.stmts[-2]
            if isinstance(stmt.lhs, RegVar) \
                    and stmt.lhs.name == 'SP' \
                    and isinstance(stmt.rhs, BinOpExp) \
                    and isinstance(stmt.rhs.e1, RegVar) \
                    and isinstance(stmt.rhs.e2, IntExp) \
                    and stmt.rhs.e1.name == 'SP':
                for i in range(len(blk.bap.stmts) - 3, -1, -1):
                    stmt = blk.bap.stmts[i]
                    if isinstance(stmt, DefStmt) \
                            and isinstance(stmt.lhs, RegVar) \
                            and isinstance(stmt.rhs, LoadExp):
                        base_pointer, offset, access = mem_addr(stmt.rhs.addr, blk, stmt.pc)
                        if base_pointer is not None and base_pointer.base_register == 'SP':
                            make_temp_offset(base_pointer.base_register, offset, blk, stmt.pc)
                            make_giv_reg(stmt.lhs.name, stmt.lhs.index, blk, stmt.pc)
                        else:
                            break
                    else:
                        break


def epilogue(blk):
    if blk.binary.config.MACHINE_ARCH == 'x86':
        x86_epilogue(blk)
    elif blk.binary.config.MACHINE_ARCH == 'x64':
        x64_epilogue(blk)
    elif blk.binary.config.MACHINE_ARCH == 'ARM':
        arm_epilogue(blk)


def x86_infer_functions(functions):
    if functions.binary.sections.has_sec(INIT):
        init_sec_addr = functions.binary.sections.get_sec(INIT).addr
        if functions.is_lowpc_function(init_sec_addr):
            _init = functions.get_function_by_lowpc(init_sec_addr)
            _init.name = '_init'
            _init.train_name = '_init'
            _init.test_name = '_init'
            _init.is_name_given = True
            _init.is_run_init = False
    if functions.binary.sections.has_sec(FINI):
        fini_sec_addr = functions.binary.sections.get_sec(FINI).addr
        if functions.is_lowpc_function(fini_sec_addr):
            _fini = functions.get_function_by_lowpc(fini_sec_addr)
            _fini.name = '_fini'
            _fini.train_name = '_fini'
            _fini.test_name = '_fini'
            _fini.is_name_given = True
            _fini.is_run_init = False
    if functions.is_lowpc_function(functions.binary.entry_point):
        _start = functions.get_function_by_lowpc(functions.binary.entry_point)
        _start.name = '_start'
        _start.train_name = '_start'
        _start.test_name = '_start'
        _start.is_name_given = True
        _start.is_run_init = False

        for blk_bap in _start.bap.blks:
            stmts = blk_bap.stmts
            for i in range(len(stmts) - 1, -1, -1):
                stmt = stmts[i]
                if isinstance(stmt, JmpStmt) \
                        and isinstance(stmt.kind, CallKind) \
                        and isinstance(stmt.kind.target, DirectLabel):
                    target_tid = stmt.kind.target.target_tid
                    called_f = functions.get_function_by_tid(target_tid)
                    if called_f is not None and called_f.name == '__libc_start_main' and i > 0:
                        main_pc = None
                        init_pc = None
                        fini_pc = None
                        for j in range(i - 2, -1, -1):
                            stmt = stmts[j]
                            if isinstance(stmt, DefStmt) \
                                    and isinstance(stmt.lhs, MemVar) \
                                    and isinstance(stmt.rhs, StoreExp) \
                                    and isinstance(stmt.rhs.exp, IntExp) \
                                    and functions.is_lowpc_function(stmt.rhs.exp.value):
                                pc = stmt.rhs.exp.value
                                if main_pc is None:
                                    main_pc = pc
                                    main = functions.get_function_by_lowpc(main_pc)
                                    if functions.binary.config.MODE == functions.binary.config.TEST:
                                        main.name = 'main'
                                        main.train_name = 'main'
                                        main.test_name = 'main'
                                        main.is_name_given = True
                                        main.is_run_init = True
                                elif init_pc is None:
                                    init_pc = pc
                                    init = functions.get_function_by_lowpc(init_pc)
                                    init.name = '__libc_csu_init'
                                    init.train_name = '__libc_csu_init'
                                    init.test_name = '__libc_csu_init'
                                    init.is_name_given = True
                                    init.is_run_init = False
                                elif fini_pc is None:
                                    fini_pc = pc
                                    fini = functions.get_function_by_lowpc(fini_pc)
                                    fini.name = '__libc_csu_fini'
                                    fini.train_name = '__libc_csu_fini'
                                    fini.test_name = '__libc_csu_fini'
                                    fini.is_name_given = True
                                    fini.is_run_init = False


def x64_infer_functions(functions):
    if functions.binary.sections.has_sec(INIT):
        init_sec_addr = functions.binary.sections.get_sec(INIT).addr
        if functions.is_lowpc_function(init_sec_addr):
            _init = functions.get_function_by_lowpc(init_sec_addr)
            _init.name = '_init'
            _init.train_name = '_init'
            _init.test_name = '_init'
            _init.is_name_given = True
            _init.is_run_init = False
    if functions.binary.sections.has_sec(FINI):
        fini_sec_addr = functions.binary.sections.get_sec(FINI).addr
        if functions.is_lowpc_function(fini_sec_addr):
            _fini = functions.get_function_by_lowpc(fini_sec_addr)
            _fini.name = '_fini'
            _fini.train_name = '_fini'
            _fini.test_name = '_fini'
            _fini.is_name_given = True
            _fini.is_run_init = False
    if functions.is_lowpc_function(functions.binary.entry_point):
        _start = functions.get_function_by_lowpc(functions.binary.entry_point)
        _start.name = '_start'
        _start.train_name = '_start'
        _start.test_name = '_start'
        _start.is_name_given = True
        _start.is_run_init = False

        for blk_bap in _start.bap.blks:
            stmts = blk_bap.stmts
            for i in range(len(stmts) - 1, -1, -1):
                stmt = stmts[i]
                if isinstance(stmt, JmpStmt) \
                        and isinstance(stmt.kind, CallKind) \
                        and isinstance(stmt.kind.target, DirectLabel):
                    target_tid = stmt.kind.target.target_tid
                    called_f = functions.get_function_by_tid(target_tid)
                    if called_f is not None and called_f.name == '__libc_start_main' and i > 0:
                        main_pc = None
                        init_pc = None
                        fini_pc = None
                        for j in range(i - 2, -1, -1):
                            stmt = stmts[j]
                            if isinstance(stmt, DefStmt):
                                if isinstance(stmt.lhs, RegVar) \
                                        and isinstance(stmt.rhs, IntExp) \
                                        and functions.is_lowpc_function(stmt.rhs.value):
                                    if stmt.lhs.name == 'RDI' and main_pc is None:
                                        main_pc = stmt.rhs.value
                                        main = functions.get_function_by_lowpc(main_pc)
                                        if functions.binary.config.MODE == functions.binary.config.TEST:
                                            main.name = 'main'
                                            main.train_name = 'main'
                                            main.test_name = 'main'
                                            main.is_name_given = True
                                            main.is_run_init = True
                                    if stmt.lhs.name == 'RCX' and init_pc is None:
                                        init_pc = stmt.rhs.value
                                        init = functions.get_function_by_lowpc(init_pc)
                                        init.name = '__libc_csu_init'
                                        init.train_name = '__libc_csu_init'
                                        init.test_name = '__libc_csu_init'
                                        init.is_name_given = True
                                        init.is_run_init = False
                                    if stmt.lhs.name == 'R8' and fini_pc is None:
                                        fini_pc = stmt.rhs.value
                                        fini = functions.get_function_by_lowpc(fini_pc)
                                        fini.name = '__libc_csu_fini'
                                        fini.train_name = '__libc_csu_fini'
                                        fini.test_name = '__libc_csu_fini'
                                        fini.is_name_given = True
                                        fini.is_run_init = False


def arm_infer_functions(functions):
    if functions.binary.sections.has_sec(INIT):
        init_sec_addr = functions.binary.sections.get_sec(INIT).addr
        if functions.is_lowpc_function(init_sec_addr):
            _init = functions.get_function_by_lowpc(init_sec_addr)
            _init.name = '_init'
            _init.train_name = '_init'
            _init.test_name = '_init'
            _init.is_name_given = True
            _init.is_run_init = False
    if functions.binary.sections.has_sec(FINI):
        fini_sec_addr = functions.binary.sections.get_sec(FINI).addr
        if functions.is_lowpc_function(fini_sec_addr):
            _fini = functions.get_function_by_lowpc(fini_sec_addr)
            _fini.name = '_fini'
            _fini.train_name = '_fini'
            _fini.test_name = '_fini'
            _fini.is_name_given = True
            _fini.is_run_init = False
    if functions.is_lowpc_function(functions.binary.entry_point):
        _start = functions.get_function_by_lowpc(functions.binary.entry_point)
        _start.name = '_start'
        _start.train_name = '_start'
        _start.test_name = '_start'
        _start.is_name_given = True
        _start.is_run_init = False

        for blk_bap in _start.bap.blks:
            stmts = blk_bap.stmts
            for i in range(len(stmts) - 1, -1, -1):
                stmt = stmts[i]
                if isinstance(stmt, JmpStmt) \
                        and isinstance(stmt.kind, CallKind) \
                        and isinstance(stmt.kind.target, DirectLabel):
                    target_tid = stmt.kind.target.target_tid
                    called_f = functions.get_function_by_tid(target_tid)
                    if called_f is not None and called_f.name == '__libc_start_main' and i > 0:
                        main_pc = None
                        init_pc = None
                        fini_pc = None
                        fini_reg = None
                        for j in range(i - 2, -1, -1):
                            stmt = stmts[j]
                            if isinstance(stmt, DefStmt):
                                if isinstance(stmt.lhs, RegVar) \
                                        and stmt.lhs.name == 'R0' \
                                        and isinstance(stmt.rhs, IntExp) \
                                        and functions.is_lowpc_function(stmt.rhs.value) \
                                        and main_pc is None:
                                    main_pc = stmt.rhs.value
                                    main = functions.get_function_by_lowpc(main_pc)
                                    if functions.binary.config.MODE == functions.binary.config.TEST:
                                        main.name = 'main'
                                        main.train_name = 'main'
                                        main.test_name = 'main'
                                        main.is_name_given = True
                                        main.is_run_init = True
                                elif isinstance(stmt.lhs, RegVar) \
                                        and stmt.lhs.name == 'R3' \
                                        and isinstance(stmt.rhs, IntExp) \
                                        and functions.is_lowpc_function(stmt.rhs.value) \
                                        and init_pc is None:
                                    init_pc = stmt.rhs.value
                                    init = functions.get_function_by_lowpc(init_pc)
                                    init.name = '__libc_csu_init'
                                    init.train_name = '__libc_csu_init'
                                    init.test_name = '__libc_csu_init'
                                    init.is_name_given = True
                                    init.is_run_init = False
                                elif isinstance(stmt.lhs, MemVar) \
                                        and isinstance(stmt.rhs, StoreExp) \
                                        and isinstance(stmt.rhs.exp, IntExp) \
                                        and functions.is_lowpc_function(stmt.rhs.exp.value) \
                                        and fini_pc is None:
                                    fini_pc = stmt.rhs.exp.value
                                    fini = functions.get_function_by_lowpc(fini_pc)
                                    fini.name = '__libc_csu_fini'
                                    fini.train_name = '__libc_csu_fini'
                                    fini.test_name = '__libc_csu_fini'
                                    fini.is_name_given = True
                                    fini.is_run_init = False
                                elif isinstance(stmt.lhs, MemVar) \
                                        and isinstance(stmt.rhs, StoreExp) \
                                        and isinstance(stmt.rhs.exp, RegVar) \
                                        and fini_pc is None \
                                        and fini_reg is None:
                                    fini_reg = (stmt.rhs.exp.name, stmt.rhs.exp.index)
                                elif isinstance(stmt.lhs, RegVar) \
                                        and isinstance(stmt.rhs, IntExp) \
                                        and functions.is_lowpc_function(stmt.rhs.value) \
                                        and fini_pc is None \
                                        and fini_reg is not None \
                                        and fini_reg == (stmt.lhs.name, stmt.lhs.index):
                                    fini_pc = stmt.rhs.value
                                    fini = functions.get_function_by_lowpc(fini_pc)
                                    fini.name = '__libc_csu_fini'
                                    fini.train_name = '__libc_csu_fini'
                                    fini.test_name = '__libc_csu_fini'
                                    fini.is_name_given = True
                                    fini.is_run_init = False


def infer_functions(functions):
    if functions.binary.config.MACHINE_ARCH == 'x86':
        x86_infer_functions(functions)
    elif functions.binary.config.MACHINE_ARCH == 'x64':
        x64_infer_functions(functions)
    elif functions.binary.config.MACHINE_ARCH == 'ARM':
        arm_infer_functions(functions)


def x86_temp_offsets(blk):
    for stmt in blk.bap.stmts:
        if stmt.insn is not None \
                and (stmt.insn.startswith('PUSH')
                     or stmt.insn.startswith('POP')
                     or stmt.insn.startswith('CALL')
                     or stmt.insn.startswith('RET')):
            if isinstance(stmt, DefStmt) \
                    and type(stmt.rhs) in (LoadExp, StoreExp):
                base_pointer, offset, access = mem_addr(stmt.rhs.addr, blk, stmt.pc)
                if base_pointer is not None and base_pointer.base_register == 'ESP':
                    make_temp_offset(base_pointer.base_register, offset, blk, stmt.pc)
            if isinstance(stmt, JmpStmt) \
                    and isinstance(stmt.kind, RetKind) \
                    and isinstance(stmt.kind.label, IndirectLabel):
                if isinstance(stmt.kind.label.exp, LoadExp):
                    base_pointer, offset, access = mem_addr(stmt.kind.label.exp, blk, stmt.pc)
                    if base_pointer is not None and base_pointer.base_register == 'ESP':
                        make_temp_offset(base_pointer.base_register, offset, blk, stmt.pc)
                elif isinstance(stmt.kind.label.exp, VirtualExp) \
                        and isinstance(get_virtual_exp(stmt.kind.label.exp, blk).exp, LoadExp):
                    base_pointer, offset, access = mem_addr(stmt.kind.label.exp, blk, stmt.pc)
                    if base_pointer is not None and base_pointer.base_register == 'ESP':
                        make_temp_offset(base_pointer.base_register, offset, blk, stmt.pc)


def x64_temp_offsets(blk):
    for stmt in blk.bap.stmts:
        if stmt.insn is not None \
                and (stmt.insn.startswith('PUSH')
                     or stmt.insn.startswith('POP')
                     or stmt.insn.startswith('CALL')
                     or stmt.insn.startswith('RET')):
            if isinstance(stmt, DefStmt) \
                    and type(stmt.rhs) in (LoadExp, StoreExp):
                base_pointer, offset, access = mem_addr(stmt.rhs.addr, blk, stmt.pc)
                if base_pointer is not None and base_pointer.base_register == 'RSP':
                    make_temp_offset(base_pointer.base_register, offset, blk, stmt.pc)
            if isinstance(stmt, JmpStmt) \
                    and isinstance(stmt.kind, RetKind) \
                    and isinstance(stmt.kind.label, IndirectLabel):
                if isinstance(stmt.kind.label.exp, LoadExp):
                    base_pointer, offset, access = mem_addr(stmt.kind.label.exp, blk, stmt.pc)
                    if base_pointer is not None and base_pointer.base_register == 'RSP':
                        make_temp_offset(base_pointer.base_register, offset, blk, stmt.pc)
                elif isinstance(stmt.kind.label.exp, VirtualExp) \
                        and isinstance(get_virtual_exp(stmt.kind.label.exp, blk).exp, LoadExp):
                    base_pointer, offset, access = mem_addr(stmt.kind.label.exp, blk, stmt.pc)
                    if base_pointer is not None and base_pointer.base_register == 'RSP':
                        make_temp_offset(base_pointer.base_register, offset, blk, stmt.pc)


def arm_temp_offsets(blk):
    pass


def temp_offsets(blk):
    if blk.binary.config.MACHINE_ARCH == 'x86':
        x86_temp_offsets(blk)
    elif blk.binary.config.MACHINE_ARCH == 'x64':
        x64_temp_offsets(blk)
    elif blk.binary.config.MACHINE_ARCH == 'ARM':
        arm_temp_offsets(blk)


def x86_syscalls(stmt, stmt_next, function):
    if isinstance(stmt, DefStmt) \
            and stmt.insn is not None \
            and stmt.insn.startswith('MOV') \
            and isinstance(stmt.lhs, RegVar) \
            and stmt.lhs.name == 'EAX' \
            and isinstance(stmt.rhs, IntExp) \
            and stmt.rhs.value in function.binary.config.SYSCALL_TABLE \
            and stmt.pc is not None \
            and function.binary.insn_map.get_pc(stmt.pc) > stmt.pc:

        syscall_value = stmt.rhs.value
        if syscall_value == 0x66:
            if isinstance(stmt_next, DefStmt) \
                    and stmt_next.insn is not None \
                    and stmt_next.insn.startswith('MOV') \
                    and isinstance(stmt_next.lhs, RegVar) \
                    and stmt_next.lhs.name == 'EBX' \
                    and isinstance(stmt_next.rhs, IntExp) \
                    and stmt_next.rhs.value in X86_SOCKETCALL_ARGS:
                function.syscalls.add(0x66 * 100 + stmt_next.rhs.value)
        else:
            if function.binary.insn_map.get_insn(function.binary.insn_map.get_pc(stmt.pc)) == 'INT':
                function.syscalls.add(syscall_value)


def x64_syscalls(stmt, function):
    if isinstance(stmt, DefStmt) \
            and stmt.insn is not None \
            and stmt.insn.startswith('MOV') \
            and isinstance(stmt.lhs, RegVar) \
            and stmt.lhs.name == 'RAX' \
            and isinstance(stmt.rhs, IntExp) \
            and stmt.rhs.value in function.binary.config.SYSCALL_TABLE \
            and stmt.pc is not None \
            and function.binary.insn_map.get_pc(stmt.pc) > stmt.pc \
            and function.binary.insn_map.get_insn(function.binary.insn_map.get_pc(stmt.pc)) == 'SYSCALL':

        function.syscalls.add(stmt.rhs.value)


def arm_syscalls(stmt, function):
    if isinstance(stmt, DefStmt) \
            and stmt.insn is not None \
            and stmt.insn.startswith('MOV') \
            and isinstance(stmt.lhs, RegVar) \
            and stmt.lhs.name == 'R7' \
            and isinstance(stmt.rhs, IntExp) \
            and stmt.rhs.value in function.binary.config.SYSCALL_TABLE \
            and stmt.pc is not None \
            and function.binary.insn_map.get_pc(stmt.pc) > stmt.pc \
            and function.binary.insn_map.get_insn(function.binary.insn_map.get_pc(stmt.pc)) == 'SVC':

        function.syscalls.add(stmt.rhs.value)


def syscalls(functions):
    added_names_count = dict()

    for function in functions.functions:
        if not function.name.startswith('sub_'):
            if function.name not in added_names_count:
                added_names_count[function.name] = 0
            added_names_count[function.name] += 1

    for function in functions.functions:
        if len(function.bap.blks) < 25:
            for blk in function.bap.blks:
                if function.binary.config.MACHINE_ARCH == 'x86':
                    if len(blk.stmts) >= 2:
                        for stmt, stmt_next in zip(blk.stmts, blk.stmts[1:]):
                            x86_syscalls(stmt, stmt_next, function)
                else:
                    for stmt in blk.stmts:
                        if function.binary.config.MACHINE_ARCH == 'x64':
                            x64_syscalls(stmt, function)
                        elif function.binary.config.MACHINE_ARCH == 'ARM':
                            arm_syscalls(stmt, function)

            if len(function.syscalls) == 1:
                syscall_value = list(function.syscalls)[0]
                function_name = function.binary.config.SYSCALL_TABLE[syscall_value]

                if function_name not in added_names_count:
                    added_names_count[function_name] = 1
                else:
                    added_names_count[function_name] += 1
                    function_name += '_' + str(added_names_count[function_name] - 1)

                # print('{} {} {} {}'.format(format(function.low_pc, '02x'), format(syscall_value, '02x'), function_name, len(function.bap.blks)))

                function.is_name_given = True
                function.is_run_init = False
                function.name = function_name
                function.train_name = function_name
                function.test_name = function_name
