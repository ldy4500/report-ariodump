all: report-airodump-ng

report-airodump-ng : main.cpp
	g++ -o airodump main.cpp -lpcap

clean:
	rm -f report-airodump-ng *.o