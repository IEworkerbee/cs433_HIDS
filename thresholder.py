"""
THRESHOLDER:
    Runs and uses log files to suggest a new config file by adjusting old config file by new metrics.
    If you change train_on_config_suggestions to true:
        It will train in place using suggested config output (as opposed to grabbing from perma config)
"""

import csv

# If false, grabs from config but still saves to suggested
TRAIN_ON_CONFIG_SUGGESTIONS = False

def get_log_data():
    """
    Returns process_data, dns_data, syn_data
    """   
    process_data = {"cpu_use": [],
                    "ave_cpu_use": [],
                    "num_children": [],
                    "rounds_active": []}
    
    dns_data = {"src": [],
                "dst": [],
                "time_stamps": []}
    
    syn_data = {"src": [],
                "dst": [],
                "time_stamps": []}

    plog = "ProcessMonitor/plog_data.csv"
    dlog = "Network/dns_log.csv"
    slog = "Network/syn_log.csv"

    # So much repitition here sorry
    with open(plog, mode='r', newline='') as file:
        reader = csv.DictReader(file, delimiter=',')
        for row in reader:
            process_data["cpu_use"].append(row['cpu_use'])
            process_data["ave_cpu_use"].append(row['ave_cpu_use'])
            process_data["num_children"].append(row['num_children'])
            process_data["rounds_active"].append(row['rounds_active'])
    
    with open(dlog, mode='r', newline='') as file:
        reader = csv.DictReader(file, delimiter=',')
        for row in reader:
            dns_data["dst"].append(row['dst'])
            dns_data["src"].append(row['src'])
            dns_data["time_stamps"].append(row['timestamp'])

    with open(slog, mode='r', newline='') as file:
        reader = csv.DictReader(file, delimiter=',')
        for row in reader:
            syn_data["dst"].append(row['dst'])
            syn_data["src"].append(row['src'])
            syn_data["time_stamps"].append(row['timestamp'])

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
    with open(f"config_suggested{config_ver}.py", "w") as file:
        for key, value in suggestions.items():
            file.write(f"{key} = {value}\n")

def get_max_frequent_cpu_usage(process_data, rounds):
    """
        Returns the maximum of the significant average cpu datas with more than or equal to rounds rounds

    """
    significant_avecpu = []
    for i in range(len(process_data["ave_cpu_use"])):
        if int(process_data["rounds_active"][i]) >= rounds:
            significant_avecpu.append(float(process_data["ave_cpu_use"][i]))

    return max(significant_avecpu)

def get_average_pings(syn_data, dns_data, SYN_TIME_WINDOW, DNS_TIME_WINDOW):
    """
    returns average_synsrc_pings_per_window, average_syndst_pings_per_window, average_dnssrc_pings_per_window, average_dnsdst_pings_per_window
    """
    max_syn_src = 0
    max_syn_dst = 0
    max_dns_src = 0
    max_dns_dst = 0

    syns = len(syn_data["src"])
    dnss = len(dns_data["src"])
    for i in range(syns):
        temp_max_syn_src = 1
        temp_max_syn_dst = 1
        for j in range(i + 1, syns):
            if float(syn_data["time_stamps"][j]) - float(syn_data["time_stamps"][i]) <= SYN_TIME_WINDOW: 
                if syn_data["src"][i] == syn_data["src"][j]:
                    temp_max_syn_src += 1
                    max_syn_src = max(max_syn_src, temp_max_syn_src)
                if syn_data["dst"][i] == syn_data["dst"][j]:
                    temp_max_syn_dst += 1
                    max_syn_dst = max(max_syn_dst, temp_max_syn_dst)
            else: 
                break

    for i in range(dnss):
        temp_max_dns_src = 1
        temp_max_dns_dst = 1
        for j in range(i + 1, dnss):
            if float(dns_data["time_stamps"][j]) - float(dns_data["time_stamps"][i]) <= DNS_TIME_WINDOW: 
                if dns_data["src"][i] == dns_data["src"][j]:
                    temp_max_dns_src += 1
                    max_dns_src = max(max_dns_src, temp_max_dns_src)
                if dns_data["dst"][i] == dns_data["dst"][j]:
                    temp_max_dns_dst += 1
                    max_dns_dst = max(max_dns_dst, temp_max_dns_dst)
            else: 
                break
    print(max_dns_dst, max_dns_src)
    return max_syn_src, max_syn_dst, max_dns_src, max_dns_dst

if __name__ == "__main__":
    process_data, dns_data, syn_data = get_log_data()

    if TRAIN_ON_CONFIG_SUGGESTIONS:
        import config_suggested0 as c
    else:
        import config as c
    suggestions = {
        "CONFIDENCE":          str(c.CONFIDENCE),
        "SYN_SRCIP_THRESHOLD": str(c.SYN_SRCIP_THRESHOLD),
        "SYN_DSTIP_THRESHOLD": str(c.SYN_DSTIP_THRESHOLD),
        "SYN_TIME_WINDOW":     str(c.SYN_TIME_WINDOW),
        "DNS_SRCIP_THRESHOLD": str(c.DNS_SRCIP_THRESHOLD),
        "DNS_DSTIP_THRESHOLD": str(c.DNS_DSTIP_THRESHOLD),
        "DNS_TIME_WINDOW":    str(c.DNS_TIME_WINDOW),
        "CPU_PERCENTAGE":      str(c.CPU_PERCENTAGE),
        "CPU_TIME_THRESHOLD":  str(c.CPU_TIME_THRESHOLD),
        "NUM_CHILDREN":        str(c.NUM_CHILDREN)
    }

    max_cpu_usage = get_max_frequent_cpu_usage(process_data, 3)
    max_num_children = int(max(process_data["num_children"]))
    avsynsrc, avsyndst, avdnssrc, avdnsdst = get_average_pings(syn_data, dns_data, c.SYN_TIME_WINDOW, c.DNS_TIME_WINDOW)
    # more confidence means less adjustment (confidence of previous data means change small)
    adjustment = 1/(c.CONFIDENCE + 1)
    suggestions["CONFIDENCE"] = str(int(suggestions["CONFIDENCE"]) + 1)
    suggestions["SYN_SRCIP_THRESHOLD"] = str(int(int(suggestions["SYN_SRCIP_THRESHOLD"]) + (adjustment * (avsynsrc - int(suggestions["SYN_SRCIP_THRESHOLD"])))))
    suggestions["SYN_DSTIP_THRESHOLD"] = str(int(int(suggestions["SYN_DSTIP_THRESHOLD"]) + (adjustment * (avsyndst - int(suggestions["SYN_DSTIP_THRESHOLD"])))))
    suggestions["DNS_SRCIP_THRESHOLD"] = str(int(int(suggestions["DNS_SRCIP_THRESHOLD"]) + (adjustment * (avdnssrc - int(suggestions["DNS_SRCIP_THRESHOLD"])))))
    suggestions["DNS_DSTIP_THRESHOLD"] = str(int(int(suggestions["DNS_DSTIP_THRESHOLD"]) + (adjustment * (avdnsdst - int(suggestions["DNS_DSTIP_THRESHOLD"])))))

    suggestions["NUM_CHILDREN"] = str(int(int(suggestions["NUM_CHILDREN"]) + (adjustment * (max_num_children - int(suggestions["NUM_CHILDREN"])))))
    suggestions["CPU_PERCENTAGE"] = str(int(int(suggestions["CPU_PERCENTAGE"]) + (adjustment * (max_cpu_usage - int(suggestions["CPU_PERCENTAGE"])))))

    suggest_config(suggestions, 0)