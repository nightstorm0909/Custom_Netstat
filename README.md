# Custom Netstat

The program is written in C to mimic "netstat -nap".

## Usage

	./custom_netstat [-t|--tcp][-u|--udp] [filter-string | "regular expression"]

If you want details of other user program files:

	sudo ./custom_netstat [-t|--tcp][-u|--udp] [filter-string | "regular expression"]