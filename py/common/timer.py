import time


class Timer:

    def __init__(self):
        self.t = 0
        self.scopes = list()
        self.scope_starts = list()
        self.runtimes = dict()

    def start(self):
        self.t = time.time()

    def end(self):
        return time.time() - self.t

    def start_scope(self, name):
        self.scopes.append(name)
        self.scope_starts.append(time.time())

    def end_scope(self):
        name = self.scopes.pop()
        start = self.scope_starts.pop()
        if name not in self.runtimes:
            self.runtimes[name] = 0
        self.runtimes[name] += time.time() - start

    def __str__(self):
        s = '\n'.join(map(lambda k: '{}: {}'.format(k, self.runtimes[k]), sorted(self.runtimes)))
        return s


TIMER = Timer()
