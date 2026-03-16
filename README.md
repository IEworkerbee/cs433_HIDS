# cs433_HIDS
CS 433 Host Based Intrusion Detection System Project

### Authors
    - Kaegan Koski
    - Henry Fleming
    - John Heibel
    
### Prerequisites

#### Windows
* npcap
  go to https://npcap.com/#download and install

#### Other
-

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
   python alert_responder.py
   ```

### Notes

Currently, certain files are not required for this to run. They are included as useful 
notes for reference as well as a lack of confidence in new work. 
