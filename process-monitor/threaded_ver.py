import psutil
import time
import os
from datetime import datetime
import threading

dump = 'dump_2'
total_t = 35
poll_t = 1

dumps = {
    'name': open(f"{dump}_name.txt", 'w+'), 
    'usr': open(f"{dump}_usr.txt", 'w+'), 
    'dir': open(f"{dump}_dir.txt", 'w+'), 
    'cpu': open(f"{dump}_cpu.txt", 'w+'),
    'files': open(f"{dump}_files.txt", 'w+')
}

mutexes = {
    'name': threading.Lock(),
    'usr': threading.Lock(),
    'dir': threading.Lock(),
    'cpu': threading.Lock(),
    'files': threading.Lock()
}

MY_PID = os.getpid()
EXCLUDED_PIDS = {MY_PID}

try:
    parent = psutil.Process(MY_PID).parent()
    while parent:
        EXCLUDED_PIDS.add(parent.pid)
        parent = parent.parent()
except (psutil.NoSuchProcess, psutil.AccessDenied):
    pass

def get_proc_name(pid):
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        
        with mutexes['name']:
            dumps['name'].write(f"{pid},{name},{str(datetime.now())}\n")
            dumps['name'].flush()
    except psutil.NoSuchProcess:
        with mutexes['name']:
            dumps['name'].write(f"ERR: proc {pid} no longer exists\n")
            dumps['name'].flush()
    except psutil.AccessDenied:
        with mutexes['name']:
            dumps['name'].write(f"ERR: cannot access proc {pid}\n")
            dumps['name'].flush()

def get_proc_usr(pid):
    try:
        proc = psutil.Process(pid)
        usr = proc.username()
        
        with mutexes['usr']:
            dumps['usr'].write(f"{pid},{usr},{str(datetime.now())}\n")
            dumps['usr'].flush()
    except psutil.NoSuchProcess:
        with mutexes['usr']:
            dumps['usr'].write(f"ERR: proc {pid} no longer exists\n")
            dumps['usr'].flush()
    except psutil.AccessDenied:
        with mutexes['usr']:
            dumps['usr'].write(f"ERR: cannot access proc {pid}\n")
            dumps['usr'].flush()

def get_proc_dir(pid):
    try:
        proc = psutil.Process(pid)
        try:
            cwd = proc.cwd()
        except psutil.NoSuchProcess:
            cwd = f"ERR: proc {pid} no longer exists"
        
        with mutexes['dir']:
            dumps['dir'].write(f"{pid},{cwd},{str(datetime.now())}\n")
            dumps['dir'].flush()
    except psutil.NoSuchProcess:
        with mutexes['dir']:
            dumps['dir'].write(f"ERR: proc {pid} no longer exists\n")
            dumps['dir'].flush()
    except psutil.AccessDenied:
        with mutexes['dir']:
            dumps['dir'].write(f"ERR: cannot access proc {pid}\n")
            dumps['dir'].flush()

def get_proc_cpu_use(pid):
    try:
        proc = psutil.Process(pid)
        cpu_use = proc.cpu_percent(interval=0.1)
        
        with mutexes['cpu']:
            dumps['cpu'].write(f"{pid},{cpu_use},{str(datetime.now())}\n")
            dumps['cpu'].flush()
    except psutil.NoSuchProcess:
        with mutexes['cpu']:
            dumps['cpu'].write(f"ERR: proc {pid} no longer exists\n")
            dumps['cpu'].flush()
    except psutil.AccessDenied:
        with mutexes['cpu']:
            dumps['cpu'].write(f"ERR: cannot access proc {pid}\n")
            dumps['cpu'].flush()

def get_proc_open_files(pid):
    try:
        proc = psutil.Process(pid)
        open_files = proc.open_files()
        formatted = ';'.join(f.path for f in open_files)
        
        with mutexes['files']:
            dumps['files'].write(f"{pid},{formatted},{str(datetime.now())}\n")
            dumps['files'].flush()
    except psutil.NoSuchProcess:
        with mutexes['files']:
            dumps['files'].write(f"ERR: proc {pid} no longer exists\n")
            dumps['files'].flush()
    except psutil.AccessDenied:
        with mutexes['files']:
            dumps['files'].write(f"ERR: cannot access proc {pid}\n")
            dumps['files'].flush()

def spawn_info_threads(pid):
    threads = []
    
    threads.append(threading.Thread(target=get_proc_name, args=(pid,), daemon=True))
    threads.append(threading.Thread(target=get_proc_usr, args=(pid,), daemon=True))
    threads.append(threading.Thread(target=get_proc_dir, args=(pid,), daemon=True))
    threads.append(threading.Thread(target=get_proc_cpu_use, args=(pid,), daemon=True))
    #threads.append(threading.Thread(target=get_proc_open_files, args=(pid,), daemon=True))

    for thread in threads:
        thread.start()

    return threads

start_time = datetime.now().timestamp()
dump_loc = open(f"{dump}.txt", "w+")
elapsed_t = 0

pids_prev = []
active_threads = []

"""for proc in psutil.process_iter(attrs=['pid']):
    try:
        pid = proc.info['pid']
        if pid not in EXCLUDED_PIDS:
            pids_prev.append(pid)
    except psutil.NoSuchProcess:
        pass

print("Done collecting initial processes!")"""

while elapsed_t < total_t:
    pids = []

    for proc in psutil.process_iter(attrs=['pid']):
        try:
            pid = proc.info['pid']
            if pid not in EXCLUDED_PIDS:
                pids.append(pid)
                if pid not in pids_prev:
                    dump_loc.write(f"New pid: {pid},{str(datetime.now())}\n")
                    info_threads = spawn_info_threads(pid)
                    active_threads.extend(info_threads)
        except:
            pass

    elapsed_t += poll_t
    if elapsed_t < total_t:
        time.sleep(poll_t)

    pids_prev = pids

for thread in active_threads:
    thread.join(timeout=5) 

dump_loc.write("\nAll done!\n")
dump_loc.write(f"Elapsed time: {datetime.now().timestamp() - start_time} vs. Expected: {total_t}")
dump_loc.close()