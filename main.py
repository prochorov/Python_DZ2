from collections import namedtuple
import time
import os


class LogLine:
    def __init__(self, zap):
        self.full = zap
        self.remote_addr = zap.partition(' -')[0]
        self.time_local = zap.partition('[')[2].partition(']')[0]
        self.request = zap.partition('] "')[2].partition('"')[0]
        self.status = zap.partition('" ')[2].partition(' ')[0]


metods = 'CONNECT DELETE GET HEAD OPTIONS POST PUT TRACE'.split()

errors = []
current_address = ""
current_time = ""
current_errors = 0

# Set the time window in seconds
time_window = 60

with open('log.txt', 'r') as file:
    for line in file:
        log_line = LogLine(line)
        if log_line.remote_addr == current_address:
            if log_line.time_local == current_time:
                current_errors += 1
                if current_errors > 4:
                    errors.append(line)
            else:
                # Check if the time difference between the current log line and the previous one is within the time window
                time_string = log_line.time_local
                if '+' not in time_string and '-' not in time_string:
                    time_string += " +0000"
                current_time_struct = time.strptime(time_string, "%d/%b/%Y:%H:%M:%S %z")
                previous_time_struct = time.strptime(current_time, "%d/%b/%Y:%H:%M:%S %z")
                time_difference = time.mktime(current_time_struct) - time.mktime(previous_time_struct)
                if time_difference <= time_window:
                    current_errors += 1
                    if current_errors > 4:
                        errors.append(line)
                else:
                    current_time = log_line.time_local
                    current_errors = 0
            if log_line.request.partition(' ')[0] not in metods:
                current_errors += 1
            if log_line.status[0] in ['4', '5']:
                current_errors += 1
        else:
            if current_errors > 0:
                with open('attack_logs.txt', 'a') as attack_logs:
                    attack_logs.write(current_address + '\n' + ''.join(errors))
                    errors = []
                current_address = log_line.remote_addr
                current_time = log_line.time_local
                current_errors = 0
                if log_line.request.partition(' ')[0] not in metods:
                    current_errors += 1
            if current_errors > 0:
                with open('attack_logs.txt', 'a') as attack_logs:
                    attack_logs.write(current_address + '\n' + ''.join(errors))


os.startfile('attack_logs.txt')
