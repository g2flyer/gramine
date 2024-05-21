# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2024 Intel Corporation
#                    Michael Steiner <michael.steiner@intel.com>
import sys
import re
import itertools
import typing
from pprint import pprint

import networkx as nx  # in python3-networkx package for ubuntu
import matplotlib.pyplot as plt
import pygraphviz as pgv  # in python3-pygraphviz package for ubuntu

import signal
timeout=60*10 # 10 minutes
def sigalrm_handler(signum, frame):
    print(f"Signal {signum} called (w. timeout={timeout}: {frame}")
    raise Exception(f"Signal {signum} called: {frame}")
signal.signal(signal.SIGALRM, sigalrm_handler)

def detect_cycles(G:nx.DiGraph):
    try:
        cycle = list(nx.find_cycle(G))
       	print("Cycles exist, e.g., ")
       	pprint(cycle)
    except nx.NetworkXNoCycle:
        print("No cycle found.")

def find_all_cycles(G:nx.DiGraph):
    #  simple_cycles can get _very_ memory hungry and lengthy, so interrupt
    #  after some timeout
    try:
        signal.alarm(timeout)
        cycles = list(nx.simple_cycles(G))
        signal.alarm(0)
        if len(cycles) > 0:
       	    print("Cycles found:")
       	    pprint(cycles)
        else:
       	     print("No cycle found.")
    except nx.NetworkXNoCycle:
        print("No cycle found.")
    except Exception as exp:
        print(f"Search of all cycles aborted: {exp}")

def find_partial_order(G:nx.DiGraph):
    try:
        partial_order = nx.topological_sort(G)
        print("Partial order found:")
        pprint(list(partial_order))
    except nx.NetworkXUnfeasible:
        print("Graph contains a cycle, so no partial order exists.")

def draw_graph(G:nx.DiGraph, filename_prefix:str = "lock_analysis.class-dependencies"):
    # - Matplotlib
    #nx.draw(G, with_labels=True)
    #nx.draw(G, with_labels=True, font_size=6, font_weight='bold', clip_on=False,)
    #nx.draw_circular(G, with_labels=True)
    #nx.draw_shell(G, with_labels=True)
    #plt.show()
    #
    # - graphviz
    A = nx.nx_agraph.to_agraph(G)
    #A.write("lock_analysis.class-dependencies.dot")
    A.draw(f"{filename_prefix}.pdf",  prog='dot')


class LockClasses(object):
    def __init__(self):
        self.classes:dict[str, 'LockClass'] = {}
        self.class_dependencies = nx.DiGraph()

    def get_class(self, name:str) -> 'LockClass':
        if name not in self.classes:
            self.classes[name] = LockClass(name)
        return self.classes[name]

class LockClass(object):
    def __init__(self, name:str):
        self.name = name
        self.instances:set['LockInstance'] = set()

    def __str__(self):
        return f"LockClass name={self.name}, instances={self.instances}"

    def __repr__(self):
        return f"{self.name}"
    

class LockInstances(object):
    def __init__(self):
        self.instances:dict[str, 'LockInstance'] = {}
        self.instance_dependencies = nx.DiGraph()

    def __get_new_active_id(self, base_id:str) -> str:
        for version in itertools.count():
            id = f"{base_id}_v{version}"
            if id not in self.instances:
                return id
            elif self.instances[id].isActive:
                print(f"WARNING: Lock {id} still active while looking for new id for base_id {base_id}!")
    
    def __get_cur_active_id(self, base_id:str) -> str:
        last_id = None
        for version in itertools.count():
            id = f"{base_id}_v{version}"
            if id not in self.instances:
                break
            last_id = id
        if last_id and self.instances[last_id].isActive:
            return last_id
        return None

    def get_instance(self, id:str) -> 'LockInstance':
        return self.instances[id]
    
    def get_active_instance(self, base_id:str) -> 'LockInstance':
        id = self.__get_cur_active_id(base_id)
        if id:
            return self.instances[id]
        else:
            return None
    
    def create_new_instance(self, base_id:str, lock_class:'LockClass', process:int) -> 'LockInstance':
        id = self.__get_new_active_id(base_id)
        instance = LockInstance(id, lock_class, process)
        self.instances[id] = instance
        lock_class.instances.add(instance)
        return instance


class LockInstance(object):
    def __init__(self, id:str, lock_class:'LockClass', process:int):
        self.id = id # assumed to be globally (spatially and temporaly acroess processes) unique
        self.lock_class = lock_class
        self.process = process # Note: process is also included in id to make id unique but we also have it here for easy access
        self.isLocked = False
        self.locking_thread = -1
        self.isActive = True
        self.uses = []

    def __str__(self):
        return f"id={self.id}, class={self.lock_class.name}, isLocked={self.isLocked}, lockingThread={self.locking_thread}, isActive={self.isActive}"

    def __repr__(self):
        return f"{self.id}"
    

    
class LockUse(object):
    def __init__(self, trace_line:int, file:str, line:int, function:str, process:int, thread:int, exec:str, cmd:str, lock:int, lock_var:str):
        self.trace_line = trace_line
        self.file = file
        self.line = line
        self.function = function
        self.process = process if process else 1  # TODO (MST): this is hack as some lock do not have process id attached but later are referenced with a process id. This hack probably doesn't work correctly with fork?
        self.thread = thread
        self.exec = exec
        self.cmd = cmd
        self.lock = lock
        self.lock_var = lock_var

    def get_location(self):
        return f"{self.file}:{self.function}:{self.line}"
    
    def get_id(self):
        return f'{self.lock}_{self.process}'
    
    def __str__(self):
        return f"lock_var={self.lock_var} lock={self.lock}, trace_line={self.trace_line} file={self.file}, line={self.line}, function={self.function}, process={self.process}, thread={self.thread}, exec={self.exec}, cmd={self.cmd}"

    def __repr__(self):
        return self.__str__()
    
class LockTrace(object):
    def __init__(self, trace_file:typing.TextIO, name:str):
        self.trace_file = trace_file
        self.name = name
        self.lock_instances = LockInstances()
        self.lock_classes = LockClasses()
        self.default_process = 0
        self.error_no_lock = set() # of (base_id, location)
        self.warning_process_guess = set() # of base_id
        self.warning_multi_lock:set['LockInstance'] = set()
        self.warning_multi_unlock:set['LockInstance'] = set()
        self.warning_no_thread:set['LockInstance'] = set()
        self.warning_unlock_thread_mismatch:set['LockInstance'] = set()
        self.warning_locked_destroy:set['LockInstance'] = set()
        self._parse()
        self._graph()
    
    process_start_pattern = \
        re.compile(r".*Gramine was built from commit.*")

    lock_line_pattern = \
        re.compile(r".*_(clear_lock|create_lock|destroy_lock|unlock|lock)\(.*")
    lock_line_parse_pattern = \
        re.compile(r"\((?P<file>.+):(?P<line>\d+):(?P<function>.*)\) "
                   r"(\[P(?P<process>\d+):(T(?P<thread>\d+):)?(?P<exec>.*)\] )?"
                   r"trace: "
                   r"_(?P<cmd>clear_lock|create_lock|destroy_lock|unlock|lock)\((?P<lock>(0|0x[0-9a-f]+))/(?P<lock_var>.+)\).*")
    
    def _parse_line(self, line:str, trace_line_num:int):
        if self.process_start_pattern.match(line):
            self.default_process += 1
        elif self.lock_line_pattern.match(line):
            m = self.lock_line_parse_pattern.match(line)
            if m:
                process = m.group('process') if m.group('process') else self.default_process
                use = LockUse(trace_line_num, m.group('file'), m.group('line'), m.group('function'), process, 
                        m.group('thread'), m.group('exec'), m.group('cmd'), m.group('lock'), m.group('lock_var'))
                if (not m.group('process')):
                    print(f"WARNING: Guessed process id '{process}' in operation [{use}] based on most recent process start!")
                    self.warning_process_guess.add(use.get_id())
                return use
            else:
                raise ValueError(f'Not a recognized lock use line: {line}')
        return None
    
    def _parse(self):
        self.lock_uses = []
        for line_number, line in enumerate(self.trace_file):
            use = self._parse_line(line.rstrip(), line_number+1)
            if use != None:
                self.lock_uses.append(use)

    def _graph(self):
        for use in self.lock_uses:
            base_id = use.get_id()
            match use.cmd:
                case 'create_lock':
                    lock_class_name = use.get_location()+"="+use.lock_var
                    lock_class = self.lock_classes.get_class(lock_class_name)
                    lock = self.lock_instances.create_new_instance(base_id, lock_class, use.process)
                    lock.uses.append(use)
                        
                case 'lock':
                    lock = self.lock_instances.get_active_instance(base_id)
                    if not(lock):
                        print(f"ERROR: Lock {base_id} in operation [{use}] not found!")
                        self.error_no_lock.add((base_id, use.lock_var))
                        continue
                    if lock.isLocked:
                        print(f"WARNING: Lock {base_id} in operation [{use}] already locked by prior operation [{lock.uses[-1]}]!")
                        self.warning_multi_lock.add(lock)
                    locking_thread = use.thread
                    if not(locking_thread):
                        print(f"WARNING: Locking lock {base_id} in operation [{use}] has no valid thread associated!")
                        self.warning_no_thread.add(lock)
                    for _, locked_lock in self.lock_instances.instances.items():
                        if locked_lock != lock and locked_lock.isLocked and locked_lock.process == lock.process and locking_thread == locked_lock.locking_thread:
                            self.lock_instances.instance_dependencies.add_edge(lock, locked_lock)
                            self.lock_classes.class_dependencies.add_edge(lock.lock_class, locked_lock.lock_class)
                    lock.isLocked = True
                    lock.locking_thread = locking_thread
                    lock.uses.append(use)

                case 'unlock':
                    lock = self.lock_instances.get_active_instance(base_id)
                    if not(lock):
                        print(f"ERROR: Lock {base_id} in operation [{use}] not found!")
                        self.error_no_lock.add((base_id, use.lock_var))
                        continue
                    if not(lock.isLocked):
                        print(f"WARNING: Lock {base_id} in operation [{use}] already unlocked by prior operation [{lock.uses[-1]}]!")
                        self.warning_multi_unlock.add(lock)
                    locking_thread = use.thread
                    if not(locking_thread):
                        print(f"WARNING: Locking lock {base_id} in operation [{use}] has no valid thread associated!")
                        self.warning_unlock_thread_mismatch.add(lock)
                    if lock.locking_thread != locking_thread:
                        print(f"WARNING: Unlocking thread {locking_thread} of lock {base_id} in operation [{use}] is different than locking thread {locking_thread} in operation [{lock.uses[-1]}]!")
                    lock.isLocked = False
                    lock.locking_thread = -1
                    lock.uses.append(use)

                case 'destroy_lock':
                    lock = self.lock_instances.get_active_instance(base_id)
                    if not(lock):
                        print(f"ERROR: Cleared Lock {base_id} not found!")
                        self.error_no_lock.add((base_id, use.lock_var))
                        continue
                    if lock.isLocked:
                        print(f"WARNING: Destroyed lock {base_id} is still locked!")
                        self.warning_locked_destroy.add(lock)
                    lock.isActive = False
                    lock.uses.append(use)
                    # every destroy_lock calls clear_lock but there are also standalone clear_locks
                    # and effectively they destroy the lock, so just handle clear_lock and ignore
                    # destroy_lock here ..
                case 'clear_lock':
                    # Note: these are only direct calls to `clear_locks`, 
                    # not indirect calls by `destroy_lock`
                    # TODO (MST): revisit whether we have to do anything for clear_lock.  
                    pass

    def analyze(self):
        print("\nSummaries from ERRORs and WARNINGs:\n-------------------------------------\n")
        print(f"missing lock:\n- {self.error_no_lock}\n")
        print(f"process guess:\n- {list((bi, i.lock_class) for i in self.lock_instances.instances.values() for bi in self.warning_process_guess if i.id.startswith(bi))}\n")
        print(f"multi-lock:\n- {self.warning_multi_lock}\n- {set(i.lock_class for i in self.warning_multi_lock)}\n")
        print(f"multi-unlock:\n- {self.warning_multi_unlock}\n- {set(i.lock_class for i in self.warning_multi_unlock)}\n")
        print(f"no-thread:\n- {list((i, (set(u.thread for u in i.uses))) for i in self.warning_no_thread)}\n- {set(i.lock_class for i in self.warning_no_thread)}\n")
        print(f"thread-mismatch:\n- {list((i, (set(u.thread for u in i.uses))) for i in self.warning_unlock_thread_mismatch)}\n- {set(i.lock_class for i in self.warning_unlock_thread_mismatch)}\n")
        print(f"locked-destroy:\n- {self.warning_locked_destroy}\n- {set(i.lock_class for i in self.warning_locked_destroy)}\n")

        print("\nLock instances dependences:\n-------------------------------------\n")
        detect_cycles(self.lock_instances.instance_dependencies)
	# find_all_cycles can be very slow and memory intensive, so do only on classes and not on instances
        print("\nLock class dependencies:\n-------------------------------------\n")
        pprint(list(self.lock_classes.class_dependencies.edges()))
        find_all_cycles(self.lock_classes.class_dependencies)
        print("\nLock class dependencies (guessed or no-thread locks removed) :\n-------------------------------------\n")
        sanitized_class_dependencies = self.lock_classes.class_dependencies.copy()
        excluded_nodes = set(i.lock_class for i in self.warning_no_thread).union(set(i.lock_class for i in self.lock_instances.instances.values() for bi in self.warning_process_guess if i.id.startswith(bi)))
        sanitized_class_dependencies.remove_nodes_from(excluded_nodes)
        print("excluded nodes=")
        pprint(excluded_nodes)
        print("resulting dependencies=")
        pprint(list(sanitized_class_dependencies.edges()))
        find_all_cycles(sanitized_class_dependencies)


if __name__ == '__main__':
    files = {}
    lock_traces = []
    if len(sys.argv) == 1:
        files["stdin"] = sys.stdin
    else:
        for file_name in sys.argv[1:]:
            files[file_name] = open(file_name, 'r')

    for name, file in files.items():
        print(f"\nTrace file {name}\n===========================================\n")
        trace = LockTrace(file, name)
        trace.analyze()
        lock_traces.append(trace)

    print(f"\nOverall Analysis\n===========================================\n")
    # Note: identical class for different traces are different objects, so we cannot just do 
    #   nx.compose_all([trace.lock_classes.class_dependencies for trace in lock_traces]) 
    # or alike but have to build a new graph (just with names)
    total_class_dependencies = nx.DiGraph()
    total_sanitized_class_dependencies = nx.DiGraph()
    for trace in lock_traces:
        for edge in trace.lock_classes.class_dependencies.edges():
            total_class_dependencies.add_edge(edge[0].name, edge[1].name)
        sanitized_class_dependencies = trace.lock_classes.class_dependencies.copy()
        excluded_nodes = set(i.lock_class for i in trace.warning_no_thread).union(set(i.lock_class for i in trace.lock_instances.instances.values() for bi in trace.warning_process_guess if i.id.startswith(bi)))
        sanitized_class_dependencies.remove_nodes_from(excluded_nodes)
        for edge in sanitized_class_dependencies.edges():
            total_sanitized_class_dependencies.add_edge(edge[0].name, edge[1].name)

    print("\nTotal Lock classes:\n-------------------------------------\n")
    pprint(total_class_dependencies.nodes())
    print("\nTotal Lock class dependencies:\n-------------------------------------\n")
    pprint(list(total_class_dependencies.edges()))
    draw_graph(total_class_dependencies, "lock_analysis.class-dependencies")
    print("\nTotal Lock class cycles and (if possible) partial order:\n-------------------------------------\n")
    find_all_cycles(total_class_dependencies)
    find_partial_order(total_class_dependencies)
    print("\nTotal Lock class dependencies (guessed or no-thread locks removed):\n-------------------------------------\n")
    pprint(list(total_sanitized_class_dependencies.edges()))
    draw_graph(total_sanitized_class_dependencies, "lock_analysis.sanitized-class-dependencies")
    print("\nLock class dependencies (guessed or no-thread locks removed) and (if possible) partial order:\n-------------------------------------\n")
    find_all_cycles(total_sanitized_class_dependencies)
    find_partial_order(total_sanitized_class_dependencies)
