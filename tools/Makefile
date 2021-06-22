CC = g++
CFLAGS = -std=c++11
objects = change_pcap2txt.cpp src/pcapRead.cpp


all: get_entropy get_alarm

get_entropy: change_pcap2txt.cpp
	$(CC) $(CFLAGS) change_pcap2txt.cpp src/pcapRead.cpp -o get_entropy.exe -lboost_program_options -lpcap

get_alarm: get_alarm_from_entropy.cpp
	$(CC) $(CFLAGS) get_alarm_from_entropy.cpp src/TrafficCharacterizer.cpp -o get_alarm.exe -lboost_program_options -lpcap

#run: $(objects)
#	$(CC) $(CFLAGS) $(objects) -o run.exe -lboost_program_options -lpcap
#	$(CC) $(CFLAGS)

#change_pcap2txt.o: change_pcap2txt.cpp
#	$(CC) $(CFLAGS) change_pcap2txt.cpp -o change_pcap2txt.o
.PHONY:clean

clean:
	rm *.exe
#	rm run
