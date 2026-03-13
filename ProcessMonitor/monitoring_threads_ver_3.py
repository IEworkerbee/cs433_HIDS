import psutil
import threading
from datetime import datetime
import os
import time
from queue import Queue
import sys

# This is a thread so I have to do special stuff
# Get the current file's directory
current_dir = os.path.dirname(os.path.realpath(__file__))
# Get the parent directory
parent_dir = os.path.dirname(current_dir)

# Add parent directory to sys.path
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import config

dump = "dump_3"
plog = "plog" # Learning Log
plog_file = open(f"ProcessMonitor/{plog}_data.csv", "w")
plog_file.write("pid,cpu_use,ave_cpu_use,num_children\n")
poll_t = 1

created = {}
cpu_uses = {}
open_files = {}

dumps = {
        'detect': open(f"{dump}_detecting.txt", "w+")
}

mutexes = {
        'detect': threading.Lock()
}

MY_PID = os.getpid()
EXCLUDED_PIDS = {MY_PID}

try:
    parent = psutil.Process(MY_PID).parent()
    while parent:
        EXCLUDED_PIDS.add(parent.pid)
        parent = psutil.Process(parent.pid).parent()
except (psutil.NoSuchProcess, psutil.AccessDenied):
    pass

def monitor_process(pid, stop_flag:threading.Event, msg_queue:Queue):
    proc_exists = 1
    proc = None
    e = None
    parent = None
    alert_raised = None

    try:
        proc = psutil.Process(pid)
        cpu_use = proc.cpu_percent(interval=None)
        name = proc.name()
        usr = proc.username()
        cwd = proc.cwd()
        create_time = proc.create_time()
        detect_time = datetime.now().timestamp()
        parent = proc.parent().pid

        created[parent] = created.get(parent, 0) + 1

        with mutexes['detect']:
            dumps['detect'].write(f"new process:{pid},parent:{parent},{name},{usr},{cwd}, created at {create_time} detected at {detect_time}\n")
    
    except:
        pass

    this_dump = open(f"dump_{pid}.txt", "w+")

    while not stop_flag.is_set() and proc_exists and alert_raised is None:
        try:
            cpu_use = proc.cpu_percent(interval=0.1)
            #files = [f.path for f in proc.open_files()]

            if pid not in cpu_uses or cpu_uses[pid] is None:
                cpu_uses[pid] = []

            if pid not in open_files or open_files[pid] is None:
                open_files[pid] = []

            cpu_uses[pid].append(cpu_use)
            #open_files[pid].append([files, datetime.now().timestamp()])

            this_dump.write(f"{cpu_use},{datetime.now().timestamp()}\n")
            plog_file.write(f"{pid},{cpu_use},{sum(cpu_uses[pid]) / len(cpu_uses[pid])},{created.get(pid, 0)}\n") # Data for thresholding
            
            if sum(cpu_uses[pid]) / len(cpu_uses[pid]) > config.CPU_PERCENTAGE and len(cpu_uses[pid]) >= config.CPU_TIME_THRESH:
                alert_raised = "sustained cpu use"
                continue
            
            if created.get(pid, 0) > config.NUM_CHILDREN:
                alert_raised = "high child count"
                continue
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            proc_exists = 0
            with mutexes['detect']:
                dumps['detect'].write(f"monitoring thread terminated for pid {pid}: {e}\n")
            continue

        time.sleep(poll_t)

    if alert_raised:
        msg_queue.put(("Process Monitor", f"From {name}: {alert_raised}"))
        with mutexes['detect']:
            dumps['detect'].write(f"alert raised for {pid}: {alert_raised}\n")

    if proc_exists:
        with mutexes['detect']:
            dumps['detect'].write(f"monitoring thread for {pid} terminated due to program ending\n")
        
    this_dump.flush()
    this_dump.close()
    return

def main_loop(msg_queue:Queue, stop_flag:threading.Event):
    monitoring_threads = []
    procs_prev = []

    for proc in psutil.process_iter(attrs=['pid', 'create_time']):
        try:
            pid = proc.info['pid']
            create_time = proc.info['create_time']

            if pid not in EXCLUDED_PIDS:
                procs_prev.append([pid, create_time])

        except psutil.NoSuchProcess:
            pass

    while not stop_flag.is_set():
        procs = []
        for proc in psutil.process_iter(attrs=['pid', 'create_time']):
            try:
                pid = proc.info['pid']
                create_time = proc.info['create_time']

                if pid not in EXCLUDED_PIDS:
                    procs.append([pid, create_time])
                    if [pid, create_time] not in procs_prev:
                        thread = threading.Thread(target=monitor_process, args=(pid, stop_flag, msg_queue), daemon=True)
                        monitoring_threads.append(thread)
                        thread.start()

            except:
                pass
            
        time.sleep(poll_t)

        procs_prev = procs

    for thread in monitoring_threads:
        thread.join(timeout=5) 
    plog_file.close()

if __name__ == "__main__":
    main_loop(None, None)