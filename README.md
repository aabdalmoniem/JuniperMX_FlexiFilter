# JuniperMX_FlexiFilter
 This sample python script, help in generating flexi-firewall filters for Juniper MX.
 
# Referance Documentation

 https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-flexible-match-conditions-overview.html 


## samples usage :
 - ./script.py --filter_type mpls --name flexi_test_mpls --label 17990
 - ./script.py --filter_type mpls --name flexi_test_mpls --ipv4 66.66.66.66 --direction src
 - ./script.py --filter_type udp --name flexi_test_1 --port 12345 --direction src
 - ./script.py --filter_type udp --name flexi_test_1 --port 12345 --direction dst

