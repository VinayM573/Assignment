import re
import csv
from collections import Counter, defaultdict

# Configurable threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(log_file_path):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)
    
    with open(log_file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(r'\b\d{1,3}(\.\d{1,3}){3}\b', line)
            if ip_match:
                ip = ip_match.group()
                ip_requests[ip] += 1
            
            # Extract endpoint (assuming it's in quotes after the HTTP method)
            endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE) (\S+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1
            
            # Detect failed login attempts (e.g., status code 401 or "Invalid credentials")
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_logins[ip] += 1
    
    return ip_requests, endpoint_requests, failed_logins

def save_results_to_csv(results, file_name):
    with open(file_name, mode='w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(results['requests_per_ip'])
        writer.writerow([])  # Blank row for separation
        
        # Write Most Accessed Endpoint
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(results['most_accessed_endpoint'])
        writer.writerow([])  # Blank row for separation
        
        # Write Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(results['suspicious_activity'])

def main():
    log_file_path = "sample.log"  # Replace with your log file path
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file_path)
    
    # Sort and prepare data for Requests per IP
    requests_per_ip = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    
    # Identify the most accessed endpoint
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])
    
    # Detect suspicious activity
    suspicious_activity = [
        (ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD
    ]
    
    # Print results
    print("Requests per IP:")
    for ip, count in requests_per_ip:
        print(f"{ip:20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity:
        print(f"{ip:20} {count}")
    
    # Save results to CSV
    results = {
        "requests_per_ip": requests_per_ip,
        "most_accessed_endpoint": most_accessed_endpoint,
        "suspicious_activity": suspicious_activity,
    }
    save_results_to_csv(results, "log_analysis_results.csv")
    print("\nResults saved to 'log_analysis_results.csv'")

if __name__ == "__main__":
    main()
