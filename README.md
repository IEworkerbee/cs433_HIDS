# cs433_HIDS
CS 433 Host Based Intrusion Detection System Project

### Authors
    - Kaegan Koski
    - John Heibel
    - Henry Fleming

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/IEworkerbee/cs433_HIDS.git
   cd cs433_HIDS
   ```
2. Create a virtual environment and activate it
   ```sh
   python -m venv .venv
   source .venv/bin/activate
   ```
3. Install python packages
   ```sh
   pip install -r requirements.txt
   ```
4. Run main monitoring program (needs root for packet sniffing)
   ```sh
   sudo python alert_responder.py
   ```
   Type `q` to quit. When a recommended action pops up, type `y` to execute or anything else to skip.

### Testing

Run any of the attack simulations in a separate terminal while the HIDS is running:
```sh
sudo python MaliciousActors/syn_flood_sim.py
sudo python MaliciousActors/dns_flood_sim.py
sudo python MaliciousActors/malformed_packet_sim.py
python ProcessMonitor/cpu-hog.py
```

### Configuration

Detection thresholds are in `Network/config.py`. Adjust as needed.
