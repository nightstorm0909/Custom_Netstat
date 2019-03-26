# Custom Netstat

The program is written in C to mimic "netstat -nap".

## Usage

Compile the code using the following command:
	
	make

Run the program with following options:

	./custom_netstat [-t|--tcp][-u|--udp] [filter-string | "regular expression"]

If you want details of other user program files:

	sudo ./custom_netstat [-t|--tcp][-u|--udp] [filter-string | "regular expression"]