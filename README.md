# entropy-p4
## Introduction
this reposity aim to estimate entropy quickly and accurately in data plane
##Getting Started
we recommend using an Ubuntu 16.04 which is our experimental machine.
This work depends on P4
you need install bmv2, p4c, and so on. 
#topo
we have configure p4-switch that all packet coming form h1 are forwarded to h2. until the end of 
observation windows, the packet with estimated entropy value will froward to h3.  
so we can capture the packet from h3 to get the estimated entropy. Note, you need take h1 as the sender as follows.

![topology](./topo/topo.JPG)
#  get entropy from bmv2
 1. in mininet CLI, type " xterm h1", open h1 windows.
 2. run
``python scripts/source1.py``, you will get the estimated entropy caculated by bmv2 switch

# get the real entropy using tools
we have provided a tool to calculate real entropy of flow.  

3. open a terminal, run ``tools/run.exe``, you need follow the data address, for example, ``./run.exe ../pcaps/s11-eth3_in.pcap``
, note that the pcap file is produced by entropy estimation ,which include the "entropy" field.
   
