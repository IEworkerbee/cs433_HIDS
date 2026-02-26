import psutil
import threading
from datetime import datetime
import os
import time

dump = "dump_3"
total_t = 60
elapsed_t = 0
poll_t = 1

dumps = {
        'monitoring': open(f"{dump}_monitoring.txt", "w+"),
        'detect': open(f"{dump}_detecting.txt", "w+")
}

mutexes = {
        'monitoring': threading.Lock(),
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

def monitor_process(pid):
    proc_exists = 1
    proc = None
    e = None

    try:
        proc = psutil.Process(pid)
        cpu_use = proc.cpu_percent(interval=None)
        name = proc.name()
        usr = proc.username()
        cwd = proc.cwd()
        create_time = proc.create_time()
        detect_time = datetime.now()

        with mutexes['detect']:
            dumps['detect'].write(f"new process:{pid},{name},{usr},{cwd}, created at {create_time} detected at {detect_time}\n")

    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        proc_exists = 0

    while proc_exists and elapsed_t < total_t:
        try:
            cpu_use = proc.cpu_percent(interval=None)
            name = proc.name()
            usr = proc.username()
            cwd = proc.cwd()
            log_time = datetime.now()

            with mutexes['monitoring']:
                dumps['monitoring'].write(f"{pid},{name},{usr},{cwd},{cpu_use},{log_time}\n")
        
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            proc_exists = 0
            with mutexes['detect']:
                dumps['detect'].write(f"monitoring thread terminated for pid {pid}: {e}\n")

        if proc_exists:
            time.sleep(poll_t)

    if proc_exists:
        with mutexes['detect']:
            dumps['detect'].write(f"monitoring thread for {pid} terminated due to program ending\n")
    
    return

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

print("Done collecting initial pids")

while elapsed_t < total_t:
    procs = []
    for proc in psutil.process_iter(attrs=['pid', 'create_time']):
        try:
            pid = proc.info['pid']
            create_time = proc.info['create_time']

            if pid not in EXCLUDED_PIDS:
                procs.append([pid, create_time])
                if [pid, create_time] not in procs_prev:
                    thread = threading.Thread(target=monitor_process, args=(pid,), daemon=True)
                    monitoring_threads.append(thread)
                    thread.start()

        except:
            pass
        
    elapsed_t += poll_t
    if elapsed_t < total_t:
        time.sleep(poll_t)

    procs_prev = procs

for thread in monitoring_threads:
    thread.join(timeout=5)    
