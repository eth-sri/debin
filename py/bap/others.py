from bap.stmts import build_stmt, PhiStmt


class Blk:
    def __init__(self, *args, **kwargs):
        self.tid = kwargs['tid']
        self.stmts = []
        for s in kwargs['stmts']:
            stmt = build_stmt(**s)
            if not (isinstance(stmt, PhiStmt) and len(stmt.rhs) == 1):
                self.stmts.append(stmt)


class Sub:
    def __init__(self, *args, **kwargs):
        self.name = kwargs['name']
        self.prog = kwargs['prog']
        self.tid = kwargs['tid']
        self.low_pc = kwargs['low_pc']
        high_pc = self.prog.binary.insn_map.get_pc(kwargs['high_pc'])
        if kwargs['high_pc'] == -1:
            self.high_pc = self.low_pc
        elif high_pc > kwargs['high_pc'] \
                and high_pc > self.low_pc:
            self.high_pc = high_pc
        else:
            self.high_pc = kwargs['high_pc']
        self.blks = [Blk(**b) for b in kwargs['blks']]
        self.cfg = [(l['src'], l['dst']) for l in kwargs['cfg']]
        self.callers = set()
        self.callees = set()

    def add_caller(self, caller):
        self.callers.add(caller)

    def add_callee(self, callee):
        self.callees.add(callee)


class Prog:
    def __init__(self, *args, **kwargs):
        self.callgraph = [(l['src'], l['dst']) for l in kwargs['callgraph']]
        self.binary = kwargs['binary']

        subs = dict([(s['tid'], Sub(**s, prog=self)) for s in kwargs['subs']])
        for src, dst in self.callgraph:
            if src in subs and dst in subs:
                subs[src].add_callee(dst)
                subs[dst].add_caller(src)
        subs = list(subs.values())
        subs = sorted(subs, key=lambda s: s.low_pc)

        if 'has_symtab' in kwargs or kwargs['has_symtab']:
            self.subs = subs
        else:
            subs_tmp = []
            i = 0
            j = 1
            callees = set(map(lambda l: l[1], self.callgraph))
            spuriouses = set()
            while i < len(subs):
                if j < len(subs):
                    if subs[j].tid not in callees \
                            and subs[j].low_pc - subs[i].low_pc <= 0x7 \
                            and subs[i].name.startswith('sub_') \
                            and subs[j].name.startswith('sub_') \
                            and not self.binary.sections.is_in_plt_sec(subs[i].low_pc) \
                            and not self.binary.sections.is_in_plt_sec(subs[j].low_pc):
                        subs[j].tid = subs[i].tid
                        subs[j].name = subs[i].name
                        subs[j].low_pc = min(subs[j].low_pc, subs[i].low_pc)
                        subs[j].high_pc = max(subs[j].high_pc, subs[i].high_pc)
                        subs[j].callers = subs[j].callers | subs[i].callers
                        subs[j].callees = subs[j].callees | subs[i].callees
                        subs_tmp.append(subs[j])
                        spuriouses.add(subs[j].tid)
                        i, j = i+2, j+2
                    else:
                        subs_tmp.append(subs[i])
                        i, j = i+1, j+1
                else:
                    subs_tmp.append(subs[i])
                    i += 1

            callees -= spuriouses

            subs_tmp1 = []
            for sub in subs_tmp:
                if self.binary.sections.is_in_plt_sec(sub.low_pc):
                    subs_tmp1.append(sub)
                elif sub.tid in callees:
                    subs_tmp1.append(sub)
                else:
                    if sub.high_pc - sub.low_pc <= 0x4:
                        spuriouses.add(sub)
                    elif self.binary.config.MACHINE_ARCH in ('x86', 'x64') \
                            and sub.low_pc % 0x10 != 0:
                        for sub1 in subs_tmp:
                            if sub.low_pc >= sub1.low_pc \
                                    and sub.high_pc <= sub1.high_pc \
                                    and sub.tid != sub1.tid:
                                spuriouses.add(sub)
                                break
                        else:
                            subs_tmp1.append(sub)
                    elif self.binary.config.MACHINE_ARCH == 'ARM' \
                            and sub.low_pc % 0x4 != 0:
                        for sub1 in subs_tmp:
                            if sub.low_pc >= sub1.low_pc \
                                    and sub.high_pc <= sub1.high_pc \
                                    and sub.tid != sub1.tid:
                                spuriouses.add(sub)
                                break
                        else:
                            subs_tmp1.append(sub)
                    else:
                        subs_tmp1.append(sub)

            for sub in subs_tmp1:
                sub.callees -= spuriouses
                sub.callers -= spuriouses

            self.subs = subs_tmp1
