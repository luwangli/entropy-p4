CC = g++
CFLAGS = -std=c++11
objects = change_pcap2txt.cpp src/pcapRead.cpp

run: $(objects)
	$(CC) $(CFLAGS) $(objects) -o run.exe -lboost_program_options -lpcap

#change_pcap2txt.o: change_pcap2txt.cpp
#	$(CC) $(CFLAGS) change_pcap2txt.cpp -o change_pcap2txt.o

clean:
	rm *.exe
#	rm run
