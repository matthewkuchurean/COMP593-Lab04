import log_analysis import get_log_file_path_from_cmd_line, filter_log_by_regex
import pandas as pd
def main():
    log_file = get_log_file_path_from_cmd_line()
    records = filter_log_by_regex(log_file, 'sshd', print_records=True)
# records = filter_log_by_regex(log_file, 'invalid user.*220.195.35.40', print_records=True)
# records = filter_log_by_regex(log_file, 'error', print_records=True)
# records = filter_log_by_regex(log_file, 'pam', print_records=True) 
# records, data = filter_log_by_regex(log_file, 'SRC=(.*?) DST=(.*?) LEN=(.*?)', print_records=True)
port_traffic = tally_port_traffic(log_file)

for port_num, count in port_traffic.items():
    
    if count >= 100:
        generate_port_traffic_report(log_file, port_num)

pass 
   
# TODO: Step 8
def tally_port_traffic(log_file):
    filter_log_by_regex(log_file, r'DPT=(.+?) ')[1] 
    port_traffic = {}
    for d in data:
        port = d[0] 
        port_traffic[port] = port_traffic.get(port, 0) + 1     
    return port_traffic

# TODO: Step 9
def generate_port_traffic_report(log_file, port_number):
    
    regex = r'(.{6}) (.{8}) .*SRC=(.+) DST=(.*+?) .+SPT=(.+) ' + f'DPT=({port_number}) '
    records, data = filter_log_by_regex(log_file,regex)[1] 
    
    report_df = pd.DataFrame(data)
    header_row = ('Data', 'Time', 'Source IP address', 'Destnation IP address', 'Source Port', 'Destination Port' )
    report_df.to_csv(f'destination_port_{port_number}_report.csv', index=False, header=header_row)
    
    
    return

# TODO: Step 11
def generate_invalid_user_report(log_file):
    report = r'(.{6}) (.{8}) .*SRC=(.+) DST=(.*+?) .+SPT=(.+) ' + f'DPT=({port_number}) '
    records, data = filter_log_by_regex(log_file,report)[1] 
    
    report_df = pd.DataFrame(data)
    header_row = ('Data', 'Time', 'Source IP address', 'Destnation IP address', 'Source Port', 'Destination Port' )
    report_df.to_csv(f'destination_port_{port_number}_report.csv', index=False, header=header_row)
    
    
    return

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):
    return

if __name__ == '__main__':
    main()