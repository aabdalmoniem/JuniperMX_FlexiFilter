# JuniperMX_FlexiFilter
 This sample python script, help in generating flexi-firewall filters for Juniper MX.
 
## Referance Documentation

 https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-flexible-match-conditions-overview.html 

## Usage
  usage: ff_gen.py [-h] --name NAME --filter_type FILTER_TYPE [--ipv4 IPV4]
  
                 [--ipv6 IPV6] [--mac MAC] [--port PORT] [--label LABEL]
                 
                 [--direction DIRECTION]
                 

  Generate FlexiFilter config for MX.
  

  optional arguments:
  
   -h, --help            show this help message and exit
   
   --name NAME           Filter name
   
   --filter_type FILTER_TYPE
   
                        Filter Type (UDP/TCP/VPLS/L2VPN/MPLS
                        
   --ipv4 IPV4           IPv4 address to match
   
   --ipv6 IPV6           IPv6 address to match
   
   --mac MAC             MAC address to match
   
   --port PORT           Port number to match
   
   --label LABEL         MPLS label to match
   
   --direction DIRECTION
   
                        src/dst port to match
                        

## Samples usage :
       ./script.py --filter_type mpls --name flexi_test_mpls --label 17990
       ./script.py --filter_type mpls --name flexi_test_mpls --ipv4 66.66.66.66 --direction src
       ./script.py --filter_type udp --name flexi_test_1 --port 12345 --direction src
       ./script.py --filter_type udp --name flexi_test_1 --port 12345 --direction dst

