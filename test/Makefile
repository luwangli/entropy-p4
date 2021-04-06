CC = g++
CFLAGS = -std=c++11
objects = main.o pcapRead.o

run: $(objects)
	$(CC) $(objects) -o  main.exe -lboost_program_options

change_pcap2txt.o: change_pcap2txt.cpp
	$(CC) $(CFLAGS) main.cpp -o main.o

clean:
	rm *.o
	rm run
