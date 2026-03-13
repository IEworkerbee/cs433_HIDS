import csv

def get_log_data():
    """
    Returns process_data, dns_data, syn_data
    """   
    process_data = {"cpu_use": [],
                    "ave_cpu_use": [],
                    "num_children": []}
    dns_data = {"src": [],
                "dst": [],
                "time_stamps": []}
    syn_data = {"src": [],
                "dst": [],
                "time_stamps": []}

    plog = "ProcessMonitor/llog_data.csv"
    dlog = "Network/dns_log.csv"
    slog = "Network/syn_log.csv"

    # So much repitition here sorry
    with open(plog, mode='r', newline='') as file:
        reader = csv.reader(file, delimiter=',')
        for row in reader:
            process_data["cpu_use"].append(row["cpu_use"])
            process_data["ave_cpu_use"].append(row["ave_cpu_use"])
            process_data["num_children"].append(row["num_children"])

    with open(slog, mode='r', newline='') as file:
        reader = csv.reader(file, delimiter=',')
        for row in reader:
            dns_data["dst"].append(row["dst"])
            dns_data["src"].append(row["src"])
            dns_data["time_stamps"].append(row["time_stamp"])

    with open(dlog, mode='r', newline='') as file:
        reader = csv.reader(file, delimiter=',')
        for row in reader:
            syn_data["dst"].append(row["dst"])
            syn_data["src"].append(row["src"])
            syn_data["time_stamps"].append(row["time_stamp"])

    return process_data, dns_data, syn_data

def suggest_config(suggestions, config_ver):
    """
        params: 
            suggestions {
                CONST_THRESHOLD: VALUE,
                CONST_THRESHOLD: VALUE,
                ...
            }

            config_ver: version number to append to suggestion

        Makes a config_suggested.py file with new thresholds
    """
    for key, value in suggestions.items():
        with open(f"config_suggested{config_ver}.py", "w") as file:
            file.write(f"{key} = {value}\n")


if __name__ == "__main__":
    process_data, dns_data, syn_data = get_log_data()