import ipaddress

# Sample blacklisted CIDR from ipsum.txt
blacklisted_cidr = "45.155.204.0/24"
# Sample IP to test (should be blacklisted if in range)
test_ip = "45.155.204.139"

# Convert to ip_network and ip_address
cidr_network = ipaddress.ip_network(blacklisted_cidr)
ip = ipaddress.ip_address(test_ip)

# Check if the IP is within the CIDR
if ip in cidr_network:
    print(f"{test_ip} is blacklisted (in {blacklisted_cidr}) ✅")
else:
    print(f"{test_ip} is NOT blacklisted ❌")
