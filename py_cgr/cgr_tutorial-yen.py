import sys
from py_cgr_lib.py_cgr_lib import cgr_yen
from py_cgr_lib.py_cgr_lib import cp_load
from py_cgr_lib.py_cgr_lib import fwd_candidate
from py_cgr_lib.py_cgr_lib import ipv6_packet
import time

source = 1          # source node A
destination = 5     # destination node E
curr_time = time.time() #current time
print(curr_time)

contact_plan = cp_load('./contact_plans/cgr_tutorial.txt', 5000)
print(contact_plan)

print("---yen---")
routes = cgr_yen(source, destination, curr_time, contact_plan, 10)
for route in routes:
    print(route)

print("---forward---")
excluded_nodes = []
ipv6_packet = ipv6_packet(src=1, dst=5, size=1, deadline=6000000, priority=8) #lower priority
candidate_routes = fwd_candidate(curr_time, source, contact_plan, ipv6_packet, routes, excluded_nodes)
print(candidate_routes[0])
print("next hop:", candidate_routes[0].next_node)