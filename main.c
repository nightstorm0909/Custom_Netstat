#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <regex.h>
#include <sys/types.h>
#include "utils.h"

struct ProcNet
{
	ino_t inode;
	struct in_addr local_addr, remote_addr;
	struct in6_addr local_addr6, remote_addr6;
	int local_port, remote_port;
	char protocol[5];
	int flag;
};
struct ProcNet *TCPdata, *UDPdata;

DIR *proc, *fd;
struct dirent *procent, *fdent;
char *filter_string, PID_line[256];

regex_t regex;
int reti;

char buf[INET_ADDRSTRLEN], buf6[INET6_ADDRSTRLEN];

int compare(const void *a, const void *b);
void display(struct ProcNet *Net, int len);
void display_at(struct ProcNet *Net, int index, const char protocol[]);

int checkTCP();
int checkUDP();

void checkProc(struct ProcNet *Net, int len, int flag, const char protocol[]);
int checkInode(struct ProcNet *Net, ino_t inode, int len);
void read_program_name_args(struct dirent *pid);
int read_program_name_args_filter(struct dirent *pid);

int main(int argc, char *argv[])
{
	int opt = 0;
	int tcp = 1, udp = 1, filter = 0, opt_flag = 0;

	static struct option long_options[] = {
		{"tcp", optional_argument, 0, 't'},
		{"udp", optional_argument, 0, 'u'},
		{0,		0,			 0,	 0}
	};
	int long_index = 0;

	while((opt = getopt_long(argc, argv, ":tu", long_options, &long_index)) != -1)
	{
		//printf("%d,", long_index);
		switch(opt)
		{
			case 't':
				tcp = 1;
				udp = 0;
				if (opt_flag)
					udp = 1;
				++opt_flag;
				
				break;
			case 'u':
				udp = 1;
				tcp = 0;
				if (opt_flag)
					tcp = 1;
				++opt_flag;
				break;
			case '?':
				printf("Usage: ./hw1 [-t|--tcp][-u|--udp] [filter-string | \"regular expression\"]\n");
				exit(1);
		}
	}

	if (optind < argc)
	{
		filter_string = argv[optind];
		filter = 1;
		//printf("filter string: %s ", filter_string);
		/* Compile regular expression */
        reti = regcomp(&regex, filter_string, 0);
        if( reti ){ fprintf(stderr, "Could not compile regex\n"); exit(1); }
	}
	//printf("\ntcp: %d, udp: %d\n", tcp, udp);

	int num_tcp, num_udp;
	
	if (tcp)
	{
		printf("\n\nList of TCP connections::: \n");
		printf("Proto \tLocal Address \t\t\tForeign Address \t\tPID/Program name and arguments\n");
		printf("---------------------------------------------------------------------------------------------------------------\n");
		num_tcp = checkTCP();
		num_tcp++;

		//display(TCPdata, num_tcp);
		//printf("\n Number of TCP: %d\n", num_tcp);
		checkProc(TCPdata, num_tcp, filter, "tcp");
	}

	if (udp)
	{
		printf("\nList of UDP connections::: \n");
		printf("Proto \tLocal Address \t\t\tForeign Address \t\tPID/Program name and arguments\n");
		printf("---------------------------------------------------------------------------------------------------------------\n");
		num_udp = checkUDP();
		num_udp++;
		checkProc(UDPdata, num_udp, filter, "udp");
	}

	return 0;
}

void display(struct ProcNet *Net, int len)
{
	for (int i = 0; i < len; ++i)
	{
		printf("%d; %s", i, Net[i].protocol);
		if (Net[i].flag)
		{
			inet_ntop(AF_INET6, &Net[i].local_addr6, buf6, sizeof(buf6));
			printf("%20s:%d", buf6, Net[i].local_port);
			inet_ntop(AF_INET6, &Net[i].remote_addr6, buf6, sizeof(buf6));
			printf("%20s", buf6);
		}
		else
		{
			if (inet_ntop(AF_INET, &Net[i].local_addr, buf, sizeof(buf)) != NULL)
				printf("%20s:%d", buf, Net[i].local_port);
			if (inet_ntop(AF_INET, &Net[i].remote_addr, buf, sizeof(buf)) != NULL)
				printf("%25s", buf);
		}
		printf(":%d\t\t", Net[i].remote_port);
		//printf(" %30u", TCPNet[i].inode);
		printf("\n");
	}
}

void display_at(struct ProcNet *Net, int index, const char protocol[])
{
	char tmp[50];
	printf("%s", Net[index].protocol);
	if (Net[index].flag)
	{
		inet_ntop(AF_INET6, &Net[index].local_addr6, buf6, sizeof(buf6));
		sprintf(tmp, "%s:%u", buf6, Net[index].local_port);
		printf("\t%-30s", tmp);
		//printf("%20s:%d", buf6, Net[index].local_port);
		inet_ntop(AF_INET6, &Net[index].remote_addr6, buf6, sizeof(buf6));
		sprintf(tmp, "%s:%u", buf6, Net[index].remote_port);
		printf("\t%-30s", tmp);
		//printf("%20s", buf6);
	}
	else
	{
		if (inet_ntop(AF_INET, &Net[index].local_addr, buf, sizeof(buf)) != NULL)
		{
			sprintf(tmp, "%s:%u", buf, Net[index].local_port);
			printf("\t%-30s", tmp);
			//printf("%20s:%d", buf, Net[index].local_port);
		}
		if (inet_ntop(AF_INET, &Net[index].remote_addr, buf, sizeof(buf)) != NULL)
		{
			sprintf(tmp, "%s:%u", buf, Net[index].remote_port);
			printf("\t%-30s", tmp);
			//printf("%25s", buf);
		}
	}
	//printf(":%d\t\t", Net[index].remote_port);
	//printf("\n");
}

int checkTCP()
{
	FILE *tcp, *tcp6;
	char line[256], local_address[16], foreign_address[16], *inode, local_port[5], foreign_port[5];

	if ((tcp = fopen("/proc/net/tcp", "r")) == NULL)
	{
		perror("tcp file stream opening failed");
		return -1;
	}
	if ((tcp6 = fopen("/proc/net/tcp6", "r")) == NULL)
	{
		perror("tcp6 file stream opening failed");
		return -3;
	}
	int size = 128;

	if ((TCPdata = calloc(size, sizeof(struct ProcNet))) == NULL)
	{
		printf("Failed to allocate memory in calloc call");
		exit(1);
	}
	fgets(line, 256, tcp);

	int num_tcp = -1;
	char delim[] = " ";

	while (fgets(line, 256, tcp))
	{
		//printf("%s", line);
		++num_tcp;
		//printf("tcp   ");
		if (num_tcp == size)
		{
			size *= 2;
			if ((TCPdata = realloc(TCPdata, (sizeof(struct ProcNet) * size))) == NULL)
			{
				perror("Failed to reallocate memory");
				exit(1);
			}
		}
		char *ptr = strtok(line, delim);
		int id = 0;
		while(ptr != NULL)
		{
			switch (id)
			{
				case 1:
					memcpy(local_address, ptr, 8);
					strncpy(local_port, ptr + 9, 4);
					local_port[4] = '\0';
					local_address[8] = '\0';
					TCPdata[num_tcp].local_addr.s_addr = hex2int(local_address);
					TCPdata[num_tcp].local_port = hex2int(local_port);
					//printf(":%d", TCPdata[num_tcp].local_port);
					break;
				case 2:
					strncpy(foreign_address, ptr, 8);
					strncpy(foreign_port, ptr + 9, 4);
					foreign_address[8] = '\0';
					foreign_port[4] = '\0';
					TCPdata[num_tcp].remote_addr.s_addr = hex2int(foreign_address);
					TCPdata[num_tcp].remote_port = hex2int(foreign_port);
					break;
				case 9:
					inode = ptr;
					TCPdata[num_tcp].inode = char2int(inode);
					break;
			}
			ptr = strtok(NULL, delim);
			++id;
		}
		strcpy(TCPdata[num_tcp].protocol, "tcp");
		TCPdata[num_tcp].flag = 0;
		//printf("\n");
	}

	char local_address6[33], foreign_address6[33];
	fgets(line, 256, tcp6);
	while (fgets(line, 256, tcp6))
	{
		//printf("%s\n", line);
		++num_tcp;
		//printf("tcp   ");
		if (num_tcp == size)
		{
			size *= 2;
			if ((TCPdata = realloc(TCPdata, (sizeof(struct ProcNet) * size))) == NULL)
			{
				perror("Failed to reallocate memory");
				exit(1);
			}
		}
		//printf("tcp6   ");
		
		char *ptr = strtok(line, delim);
		int id = 0;
		while(ptr != NULL)
		{
			switch (id)
			{
				case 1:
					strncpy(local_address6, ptr, 32);
					strncpy(local_port, ptr + 33, 4);
					local_port[4] = '\0';
					local_address6[32] = '\0';
					TCPdata[num_tcp].local_port = hex2int(local_port);
					if (sscanf(local_address6, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
									&TCPdata[num_tcp].local_addr6.s6_addr[3], &TCPdata[num_tcp].local_addr6.s6_addr[2], &TCPdata[num_tcp].local_addr6.s6_addr[1], 
									&TCPdata[num_tcp].local_addr6.s6_addr[0], &TCPdata[num_tcp].local_addr6.s6_addr[7], &TCPdata[num_tcp].local_addr6.s6_addr[6],
									&TCPdata[num_tcp].local_addr6.s6_addr[5], &TCPdata[num_tcp].local_addr6.s6_addr[4],	&TCPdata[num_tcp].local_addr6.s6_addr[11], 
									&TCPdata[num_tcp].local_addr6.s6_addr[10], &TCPdata[num_tcp].local_addr6.s6_addr[9], &TCPdata[num_tcp].local_addr6.s6_addr[8],
									&TCPdata[num_tcp].local_addr6.s6_addr[15], &TCPdata[num_tcp].local_addr6.s6_addr[14], &TCPdata[num_tcp].local_addr6.s6_addr[13], 
									&TCPdata[num_tcp].local_addr6.s6_addr[12]) == 16)
					{
						inet_ntop(AF_INET6, &TCPdata[num_tcp].local_addr6, buf6, sizeof(buf6));
					}
					//printf("%s:%u", buf6, TCPdata[num_tcp].local_port);
					break;
				case 2:
					strncpy(foreign_address6, ptr, 32);
					strncpy(foreign_port, ptr + 33, 4);
					foreign_port[4] = '\0';
					foreign_address6[32] = '\0';
					TCPdata[num_tcp].remote_port = hex2int(foreign_port);
					if (sscanf(local_address6, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
									&TCPdata[num_tcp].remote_addr6.s6_addr[3], &TCPdata[num_tcp].remote_addr6.s6_addr[2], &TCPdata[num_tcp].remote_addr6.s6_addr[1], 
									&TCPdata[num_tcp].remote_addr6.s6_addr[0], &TCPdata[num_tcp].remote_addr6.s6_addr[7], &TCPdata[num_tcp].remote_addr6.s6_addr[6],
									&TCPdata[num_tcp].remote_addr6.s6_addr[5], &TCPdata[num_tcp].remote_addr6.s6_addr[4], &TCPdata[num_tcp].remote_addr6.s6_addr[11], 
									&TCPdata[num_tcp].remote_addr6.s6_addr[10], &TCPdata[num_tcp].remote_addr6.s6_addr[9], &TCPdata[num_tcp].remote_addr6.s6_addr[8],
									&TCPdata[num_tcp].remote_addr6.s6_addr[15], &TCPdata[num_tcp].remote_addr6.s6_addr[14], &TCPdata[num_tcp].remote_addr6.s6_addr[13], 
									&TCPdata[num_tcp].remote_addr6.s6_addr[12]) == 16)
					{
						inet_ntop(AF_INET6, &TCPdata[num_tcp].remote_addr6, buf6, sizeof(buf6));
					}
					//printf("\t\t%s:%u", buf6, TCPdata[num_tcp].remote_port);
					break;
				case 9:
					inode = ptr;
					TCPdata[num_tcp].inode = char2int(inode);
					//printf("\t\t\t%u", TCPdata[num_tcp].inode);
					break;
			}
			ptr = strtok(NULL, delim);
			++id;
		}
		strcpy(TCPdata[num_tcp].protocol, "tcp6");
		//printf("\n\n");
		TCPdata[num_tcp].flag = 1;
	}
	//printf("Number of tcp: %d\n", num_tcp);

	fclose(tcp);
	fclose(tcp6);
	return num_tcp;
}

int checkUDP()
{
	FILE *udp, *udp6;
	char line[256], local_address[16], foreign_address[16], *inode, local_port[5], foreign_port[5];

	if ((udp = fopen("/proc/net/udp", "r")) == NULL)
	{
		perror("udp file stream opening failed");
		return -2;
	}
	if ((udp6 = fopen("/proc/net/udp6", "r")) == NULL)
	{
		perror("udp6 file stream opening failed");
		return -2;
	}
	char delim[] = " ";
	int size = 128;

	if ((UDPdata = calloc(size, sizeof(struct ProcNet))) == NULL)
	{
		printf("Failed to allocate memory in calloc call");
		exit(1);
	}
	//printf("Size of UDPdata: %u, %u\n", sizeof(UDPdata), sizeof(struct ProcNet));
	int num_udp = -1;
		
	fgets(line, 256, udp);
	while (fgets(line, 256, udp))
	{
		//printf("%s\n", line);
		++num_udp;
		if (num_udp == size)
		{
			size *= 2;
			if ((UDPdata = realloc(UDPdata, (sizeof(struct ProcNet) * size))) == NULL)
			{
				perror("Failed to reallocate memory");
				exit(1);
			}
		}
		char *ptr = strtok(line, delim);
		int id = 0;
		while(ptr != NULL)
		{
			switch (id)
			{
				case 1:
					strncpy(local_address, ptr, 8);
					strncpy(local_port, ptr + 9, 4);
					local_port[4] = '\0';
					local_address[8] = '\0';
					UDPdata[num_udp].local_addr.s_addr = hex2int(local_address);
					UDPdata[num_udp].local_port = hex2int(local_port);
					break;
				case 2:
					strncpy(foreign_address, ptr, 8);
					strncpy(foreign_port, ptr + 9, 4);
					foreign_address[8] = '\0';
					foreign_port[4] = '\0';
					UDPdata[num_udp].remote_addr.s_addr = hex2int(foreign_address);
					UDPdata[num_udp].remote_port = hex2int(foreign_port);
					break;
				case 9:
					inode = ptr;
					UDPdata[num_udp].inode = char2int(inode);
					break;
			}
			//printf("'%s'\n", ptr);
			ptr = strtok(NULL, delim);
			++id;
		}
		strcpy(UDPdata[num_udp].protocol, "udp");
		UDPdata[num_udp].flag = 0;
		//printf("\n");
	}
	//printf("Size of UDPdata: %u, %u, %d\n", sizeof(UDPdata), sizeof(struct ProcNet), num_udp);

	char local_address6[33], foreign_address6[33];
	fgets(line, 256, udp6);
	while (fgets(line, 256, udp6))
	{
		//printf("%s\n", line);
		++num_udp;
		//printf("tcp   ");
		if (num_udp == size)
		{
			size *= 2;
			if ((UDPdata = realloc(UDPdata, (sizeof(struct ProcNet) * size))) == NULL)
			{
				perror("Failed to reallocate memory");
				exit(1);
			}
		}
		//printf("tcp6   ");
		
		char *ptr = strtok(line, delim);
		int id = 0;
		while(ptr != NULL)
		{
			switch (id)
			{
				case 1:
					strncpy(local_address6, ptr, 32);
					strncpy(local_port, ptr + 33, 4);
					local_port[4] = '\0';
					local_address6[32] = '\0';
					UDPdata[num_udp].local_port = hex2int(local_port);
					if (sscanf(local_address6, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
									&UDPdata[num_udp].local_addr6.s6_addr[3], &UDPdata[num_udp].local_addr6.s6_addr[2], &UDPdata[num_udp].local_addr6.s6_addr[1], 
									&UDPdata[num_udp].local_addr6.s6_addr[0], &UDPdata[num_udp].local_addr6.s6_addr[7], &UDPdata[num_udp].local_addr6.s6_addr[6],
									&UDPdata[num_udp].local_addr6.s6_addr[5], &UDPdata[num_udp].local_addr6.s6_addr[4],	&UDPdata[num_udp].local_addr6.s6_addr[11], 
									&UDPdata[num_udp].local_addr6.s6_addr[10], &UDPdata[num_udp].local_addr6.s6_addr[9], &UDPdata[num_udp].local_addr6.s6_addr[8],
									&UDPdata[num_udp].local_addr6.s6_addr[15], &UDPdata[num_udp].local_addr6.s6_addr[14], &UDPdata[num_udp].local_addr6.s6_addr[13], 
									&UDPdata[num_udp].local_addr6.s6_addr[12]) == 16)
					{
						inet_ntop(AF_INET6, &UDPdata[num_udp].local_addr6, buf6, sizeof(buf6));
					}
					//printf("%s:%u", buf6, UDPdata[num_udp].local_port);
					break;
				case 2:
					strncpy(foreign_address6, ptr, 32);
					strncpy(foreign_port, ptr + 33, 4);
					foreign_port[4] = '\0';
					foreign_address6[32] = '\0';
					UDPdata[num_udp].remote_port = hex2int(foreign_port);
					if (sscanf(local_address6, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
									&UDPdata[num_udp].remote_addr6.s6_addr[3], &UDPdata[num_udp].remote_addr6.s6_addr[2], &UDPdata[num_udp].remote_addr6.s6_addr[1], 
									&UDPdata[num_udp].remote_addr6.s6_addr[0], &UDPdata[num_udp].remote_addr6.s6_addr[7], &UDPdata[num_udp].remote_addr6.s6_addr[6],
									&UDPdata[num_udp].remote_addr6.s6_addr[5], &UDPdata[num_udp].remote_addr6.s6_addr[4], &UDPdata[num_udp].remote_addr6.s6_addr[11], 
									&UDPdata[num_udp].remote_addr6.s6_addr[10], &UDPdata[num_udp].remote_addr6.s6_addr[9], &UDPdata[num_udp].remote_addr6.s6_addr[8],
									&UDPdata[num_udp].remote_addr6.s6_addr[15], &UDPdata[num_udp].remote_addr6.s6_addr[14], &UDPdata[num_udp].remote_addr6.s6_addr[13], 
									&UDPdata[num_udp].remote_addr6.s6_addr[12]) == 16)
					{
						inet_ntop(AF_INET6, &UDPdata[num_udp].remote_addr6, buf6, sizeof(buf6));
					}
					//printf("\t\t%s:%u", buf6, UDPdata[num_udp].remote_port);
					break;
				case 9:
					inode = ptr;
					UDPdata[num_udp].inode = char2int(inode);
					//printf("\t\t\t%u", UDPdata[num_udp].inode);
					break;
			}
			ptr = strtok(NULL, delim);
			++id;
		}
		strcpy(UDPdata[num_udp].protocol, "udp6");
		//printf("\n\n");
		UDPdata[num_udp].flag = 1;
	}
	fclose(udp);
	fclose(udp6);
	return num_udp;
}

void checkProc(struct ProcNet *Net, int len, int flag, const char protocol[])
{
	char path[1000], buf2[256], link[64], tmp[10], inode[15], p_name[512];
	int ret;
	//ino_t inode;
	ssize_t link_size;
	//printf("flag: %d\n", flag);

	if ((proc = opendir("/proc")) == NULL)
	{
		perror("Cannot open /proc directory\n");
		exit(1);
	}

	while ((procent = readdir(proc)) != NULL)
	{
		if (!isdigit(*(procent->d_name)))
			continue;
		sprintf(buf2, "/proc/%s/fd", procent->d_name);
		//printf("%s\n", buf2);

		if ((fd = opendir(buf2)) == NULL)
			continue;
		while((fdent = readdir(fd)) != NULL)
		{
			struct stat st;

			sprintf(buf2, "/proc/%s/fd/%s", procent->d_name, fdent->d_name);
			if (stat(buf2, &st) < 0)
				continue;
			if (!S_ISSOCK(st.st_mode))
				continue;
			ret = checkInode(Net, st.st_ino, len);
			if (ret >= 0)
			{
				if (flag)
				{
					if (read_program_name_args_filter(procent))
					{
						display_at(Net, ret, protocol);
						printf("%s/", procent->d_name);
						read_program_name_args(procent);
					}
				}
				else
				{	
					display_at(Net, ret, protocol);
					printf("%s/", procent->d_name);
					read_program_name_args(procent);
				//printf("%s", p_name);
				}
			}
		}
		closedir(fd);
	}	
	//printf("here\n");
	closedir(proc);
}

int checkInode(struct ProcNet *Net, ino_t inode, int len)
{
	for (int i = 0; i < len; ++i)
	{
		if (Net[i].inode == inode)
		{
			//printf("%u, ", Net[i].inode);
			return i;
		}
	}
	return -1;
}

void read_program_name_args(struct dirent *pid)
{
	char prog_name[300], buf3[50];//, line[256];
	FILE *tmp;
	char tmp2[] = "/";
	sprintf(buf3, "/proc/%s/cmdline", pid->d_name);
	if ((tmp = fopen(buf3, "r")) == NULL)
	{
		perror("cannot open /proc/PID/cmdline file");
		//exit(3);
	}
	fgets(PID_line, sizeof(PID_line), tmp);
	char *ptr = strtok(PID_line, tmp2);
	while(ptr != NULL)
	{
		strcpy(prog_name, ptr);
		ptr = strtok(NULL, tmp2);
	}
	//printf("%s\n\n", PID_line);
	printf("%s\n\n", prog_name);
	fclose(tmp);
	//return line;
}

int read_program_name_args_filter(struct dirent *pid)
{
	char prog_name[300], buf3[50];//, line[256];
	FILE *tmp;
	char tmp2[] = "/";
	int i = 1;
	sprintf(buf3, "/proc/%s/cmdline", pid->d_name);
	if ((tmp = fopen(buf3, "r")) == NULL)
	{
		perror("cannot open /proc/PID/cmdline file");
		//exit(3);
	}
	fgets(PID_line, sizeof(PID_line), tmp);
	char *ptr = strtok(PID_line, tmp2);
	while(ptr != NULL)
	{
		strcpy(prog_name, ptr);
		ptr = strtok(NULL, tmp2);
	}
	//reti = regexec(&regex, PID_line, 0, NULL, 0);
	reti = regexec(&regex, prog_name, 0, NULL, 0);
    if( !reti )
	{
		fclose(tmp);
		return 1;
	}
    else
    {
		
		fclose(tmp);
		return 0;
	}
}

/*
int read_program_name_args_filter(struct dirent *pid)
{
	char *prog_name, buf3[50];//, line[256];
	FILE *tmp;
	int i = 1;
	sprintf(buf3, "/proc/%s/cmdline", pid->d_name);
	if ((tmp = fopen(buf3, "r")) == NULL)
	{
		perror("cannot open /proc/PID/cmdline file");
		//exit(3);
	}
	fgets(PID_line, sizeof(PID_line), tmp);
	if (strstr(PID_line, filter_string) == NULL)
	{
		fclose(tmp);
		return 0;
	}
	else
	{
		fclose(tmp);
		return 1;
	}
}
*/