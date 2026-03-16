from plyer import notification
from queue import Queue, Empty
import threading
from Network.dns_flood_sniffer import run_dns_flood_sniffer
from Network.malformed_packet_sniffer import run_malformed_packet_sniffer
from Network.syn_flood_sniffer import run_syn_flood_sniffer
from ProcessMonitor.monitoring_threads_ver_3 import main_loop
import os

IS_SHUTDOWN = False
STOPFLAG = threading.Event()
msg_queue = Queue()
action_queue = Queue()
input_queue = Queue()
local_log = {}

# recommended actions mapped to shell commands
ACTIONS = {
    "block_ip":    lambda ip: f"sudo iptables -A INPUT -s {ip} -j DROP",
    "kill_process": lambda pid: f"kill {pid}",
    "block_port":  lambda port: f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP",
}

def alert(message):
    notification.notify(
        title = message[0],
        message = message[1],
        app_name = "CS433 HIDS Alert System",
        app_icon = None
    )   

# reads stdin in a thread so the main loop can stay non-blocking
def input_reader(q):
    while True:
        try:
            q.put(input())
        except EOFError:
            break

# listens for alerts and pushes recommended actions
def listener_thread(msg_queue, action_queue):
    buffer = ""
    while True:
        message = msg_queue.get(block = True) # message of form (title, msg, action) or (title, msg)
        if message == None:
            break
        title, body, *rest = message
        action = rest[0] if rest else None
        if message[0] in local_log:
            local_log[message[0]] += 1
        else:
            local_log[message[0]] = 1 
        if message != buffer:
            buffer = message
            alert((title, body))

            # queue up the recommended action if there is one
            if action:
                action_type, arg = action
                cmd = ACTIONS[action_type](arg)
                action_queue.put((body, cmd))

        msg_queue.task_done()

def stop_listener(eventflag):
    eventflag.wait()

# TODO: Possibly remove these. I know they are silly, but they help conceptualize where the processes are
# -------------------------------------------
def malformed_thread(msg_queue, stop_flag):
    run_malformed_packet_sniffer(msg_queue, stop_flag)

def syn_thread(msg_queue, stop_flag):
    run_syn_flood_sniffer(msg_queue, stop_flag)

def dns_thread(msg_queue, stop_flag):
    run_dns_flood_sniffer(msg_queue, stop_flag)

def proc_thread(msg_queue, stop_flag):
    main_loop(msg_queue, stop_flag)
# -------------------------------------------

if __name__ == '__main__':
    listener = threading.Thread(target=listener_thread, args=(msg_queue, action_queue,))
    detector_0 = threading.Thread(target=malformed_thread, args=(msg_queue,STOPFLAG,))
    detector_1 = threading.Thread(target=syn_thread, args=(msg_queue,STOPFLAG,))
    detector_2 = threading.Thread(target=dns_thread, args=(msg_queue,STOPFLAG,))
    cpu_detector = threading.Thread(target=proc_thread, args=(msg_queue,STOPFLAG,))
    stop_thread = threading.Thread(target=stop_listener, args=(STOPFLAG,))
    stdin_thread = threading.Thread(target=input_reader, args=(input_queue,), daemon=True)

    listener.start()
    detector_0.start()
    detector_1.start()
    detector_2.start()
    cpu_detector.start()
    stop_thread.start()
    stdin_thread.start()

    print("HIDS running. type 'q' to quit.")

    # main loop handles user input and pending recommended actions
    pending = None
    while IS_SHUTDOWN == False:
        # pick up a new action if we're not already prompting
        if pending is None:
            try:
                desc, cmd = action_queue.get_nowait()
                pending = cmd
                print(f"\n  [{desc}]")
                print(f"  recommended: {cmd}")
                print(f"  execute? [y/N] ", end="", flush=True)
            except Empty:
                pass

        # check for user input
        try:
            user_input = input_queue.get(timeout=0.5)
            if user_input.strip().lower() == 'q':
                IS_SHUTDOWN = True
                STOPFLAG.set()
                break
            elif pending and user_input.strip().lower() == 'y':
                os.system(pending)
                pending = None
            elif pending:
                print("  skipped.")
                pending = None
        except Empty:
            pass

    stop_thread.join()
    msg_queue.put(None)
    detector_0.join()
    detector_1.join()
    detector_2.join()
    cpu_detector.join()
    listener.join()
    print(local_log)