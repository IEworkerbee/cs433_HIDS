from plyer import notification
from queue import Queue
import threading
from Network.dns_flood_sniffer import run_dns_flood_sniffer
from Network.malformed_packet_sniffer import run_malformed_packet_sniffer
from Network.syn_flood_sniffer import run_syn_flood_sniffer

IS_SHUTDOWN = False
STOPFLAG = threading.Event()
msg_queue = Queue()

def alert(message):
    notification.notify(
        title = message[0],
        message = message[1],
        app_name = "CS433 HIDS Alert System",
        app_icon = None
    )

# Adds Queue Tasks
def listener_thread(msg_queue):
    message = msg_queue.get() # message of form (title, msg)
    if message != None:
        alert(message)
    msg_queue.task_done()

def stop_listener(eventflag):
    eventflag.wait()

def malformed_thread(msg_queue, stop_flag):
    run_malformed_packet_sniffer(msg_queue, stop_flag)

def syn_thread(msg_queue, stop_flag):
    run_syn_flood_sniffer(msg_queue, stop_flag)

def dns_thread(msg_queue, stop_flag):
    run_dns_flood_sniffer(msg_queue, stop_flag)

if __name__ == '__main__':
    listener = threading.Thread(target=listener_thread, args=(msg_queue,))
    detector_0 = threading.Thread(target=malformed_thread, args=(msg_queue,STOPFLAG,))
    detector_1 = threading.Thread(target=syn_thread, args=(msg_queue,STOPFLAG,))
    detector_2 = threading.Thread(target=dns_thread, args=(msg_queue,STOPFLAG,))
    stop_thread = threading.Thread(target=stop_listener, args=(STOPFLAG,))

    listener.start()
    detector_0.start()
    detector_1.start()
    detector_2.start()
    stop_thread.start()

    while IS_SHUTDOWN == False:
        input = input()
        if input == 'q':
            IS_SHUTDOWN = True
            STOPFLAG.set()
            break

    stop_thread.join()
    msg_queue.put(None)
    detector_0.join()
    detector_1.join()
    detector_2.join()
    listener.join()