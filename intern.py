import csv
import re
from collections import defaultdict

# File path to the sample log file
log_file_path = 'sample.log'  # Ensure this points to your actual log file

# Threshold for failed login attempts (adjusted for testing)
failed_login_threshold = 2  # Temporarily reduce to 2 for testing

# Dictionaries to store data
ip_requests = defaultdict(int)
endpoint_access = defaultdict(int)
failed_logins = defaultdict(int)

# Regular expression for parsing log entries
log_pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "(GET|POST|PUT|DELETE) (\S+) HTTP/1.1" (\d{3}) (\d+)'

# Read the log file and process each line
with open(log_file_path, 'r') as log_file:
    for line in log_file:
        match = re.match(log_pattern, line)
        if match:
            ip_address, timestamp, method, endpoint, status_code, response_size = match.groups()
            
            # Count requests per IP address
            ip_requests[ip_address] += 1
            
            # Count the most accessed endpoint
            endpoint_access[endpoint] += 1
            
            # Check for failed login attempts (status 401 or 'Invalid credentials')
            if status_code == '401':
                failed_logins[ip_address] += 1
                print(f"Detected failed login for IP {ip_address}: {failed_logins[ip_address]}")  # Debugging

# Write the results to CSV file
with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    
    # Write Requests per IP Address section
    writer.writerow(['IP Address', 'Request Count'])
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        writer.writerow([ip, count])
    
    # Write Most Accessed Endpoint section
    writer.writerow(['Endpoint', 'Access Count'])
    most_accessed_endpoint = max(endpoint_access, key=endpoint_access.get, default=None)
    writer.writerow([most_accessed_endpoint, endpoint_access.get(most_accessed_endpoint, 0)])
    
    # Write Suspicious Activity section
    writer.writerow(['IP Address', 'Failed Login Count'])
    for ip, failed_count in failed_logins.items():
        if failed_count >= failed_login_threshold:
            writer.writerow([ip, failed_count])

print("Analysis complete and results saved to 'log_analysis_results.csv'.")
