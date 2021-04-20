# entropy-p4
## Introduction
this reposity aim to estimate entropy quickly and accurately in data plane
##Getting Started
we recommend using an Ubuntu 16.04 which is our experimental machine.
This work depends on P4
you need install bmv2, p4c, and so on. 
# run
 1. in mininet CLI, type " xterm h1", open h1 windows.
 2. run
``python scripts/source1.py``, you will get the estimated entropy caculated by bmv2 switch
    
3. then open a terminal, run ``tools/run.exe``, you need follow the data address, for example, ``./run.exe ../pcaps/s11-eth3_in.pcap``
, note that the pcap file is produced by entropy estimation ,which include the "entropy" field.
   
