class InsnMap:

    def __init__(self, *args, **kwargs):
        self.pc_dict = dict()
        self.insn_dict = dict()
        if 'pcs' in kwargs:
            for item in kwargs['pcs']:
                self.add_pc(item['start_pc'], item['byte_length'], item['insn_name'])

    def add_pc(self, start_pc, byte_length, insn_name):
        self.pc_dict[start_pc] = start_pc + byte_length
        self.insn_dict[start_pc] = insn_name

    def get_pc(self, pc):
        return self.pc_dict[pc] if pc in self.pc_dict else pc

    def get_insn(self, pc):
        return self.insn_dict[pc] if pc in self.insn_dict else None
