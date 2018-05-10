========================================================================
README for Intel(R) sim Package

February 2018
========================================================================


Contents
========

Contains source modules for simulated components which are used for test purposes
        - WAG-simulator, VNF-delay-simulation

Overview
========

This application can be used at three way
1) GRE and Forwarding (WAG simulator). option: --mode gre-and-fwd
In this mode all packeges come from first PHY interface (VNF-D) will decapsulated and sent to 
second PHY interface (to internet for example), all pactes came from second phy interface will 
encapulated to GRE tunnel and sent to first PHY interface. For work in this mode your must setup 
MAC address of output interface in the function pkt_for_iperf.

2) Loopback. option: --mode loopback
In this mode all packets will returned to interface after swap MAC and IP addresses

3) Delay simulator. option: --mode delay
In this mode all packets wait some time before send. Work like WAG simulator, but have additional pause.


How to build
============

For build your must define environment variable RTE_SDK - path to your DPDK
run make

How to run
==========
This module can be used in 3 seperate modes as a simulator.
* WAG simulator to swap MAC addresses and loopback packets.
* Wag simulator to GRE encap/decap and forward packets.
* Delay simulator to delay packets for time period based on IP address.


run it by following the usage message. Below are some example commands.

./build/rwpa_test_sim -c 0xe0 -w 05:00.1 -w 05:00.2 --socket-mem 256 --file-prefix fakeapp -- -p 0x3 --mode gre-and-fwd

./build/rwpa_test_sim -c 0xe0 -w 05:00.1 --socket-mem 256 --file-prefix fakeapp -- -p 0x1 --mode loopback

./rwpa_test_sim -c 0xc -w 00:0a.0 -w 00:0b.0 --socket-mem 1024 --file-prefix delayAB -- -p 0x3 --mode delay --delay-a 100000 --delay-b 50000 --ip-b 192.168.1.103 --delay-noneip 192.168.1.121


Legal Disclaimer
================

THIS SOFTWARE IS PROVIDED BY INTEL"AS IS". NO LICENSE, EXPRESS OR
IMPLIED, BY ESTOPPEL OR OTHERWISE, TO ANY INTELLECTUAL PROPERTY RIGHTS
ARE GRANTED THROUGH USE. EXCEPT AS PROVIDED IN INTEL'S TERMS AND
CONDITIONS OF SALE, INTEL ASSUMES NO LIABILITY WHATSOEVER AND INTEL
DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY, RELATING TO SALE AND/OR
USE OF INTEL PRODUCTS INCLUDING LIABILITY OR WARRANTIES RELATING TO
FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABILITY, OR INFRINGEMENT
OF ANY PATENT, COPYRIGHT OR OTHER INTELLECTUAL PROPERTY RIGHT.
