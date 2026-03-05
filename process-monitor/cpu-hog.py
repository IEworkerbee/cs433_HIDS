# test_cpu_hog.py
import multiprocessing
import time
import os

def burn_cpu():
    """Waste CPU cycles"""
    end_time = time.time() + 30  # Run for 30 seconds
    while time.time() < end_time:
        _ = sum(range(10000000))

if __name__ == "__main__":
    # Spawn multiple processes to use all cores
    print(os.getpid())
    num_cores = multiprocessing.cpu_count()
    processes = []
    
    print(f"Starting {num_cores} CPU-intensive processes...")
    for _ in range(num_cores):
        p = multiprocessing.Process(target=burn_cpu)
        p.start()
        processes.append(p)
    
    for p in processes:
        p.join()
    
    print("Test complete")