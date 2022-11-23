#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#define NTDDI_VERSION 0x0A00000A
#define _WIN32_WINNT 0x0A00

#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <WS2tcpip.h>
#include<winsock.h>

#ifdef _WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

/* Print all the available information on the given interface */
void ifprint(pcap_if_t* d)
{
	pcap_addr_t* a;
	char ip6str[128];

	/* Name */
	printf("%s\n", d->name);

	/* Description */
	if (d->description)
		printf("\tDescription: %s\n", d->description);

	/* Loopback Address*/
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);
		char buf[100];
		memset(buf, 0, 100);

		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr) {
				inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr.s_addr, buf, 100);
				printf("\tAddress: %s\n", buf);
				memset(buf, 0, 100);
			}
			if (a->netmask) {
				inet_ntop(AF_INET, &((struct sockaddr_in*)a->netmask)->sin_addr.s_addr, buf, 100);
				printf("\tNetmask: %s\n", buf);
				memset(buf, 0, 100);
			}
			if (a->broadaddr) {
				inet_ntop(AF_INET, &((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr, buf, 100);
				printf("\tBroadcast Address: %s\n", buf);
				memset(buf, 0, 100);
			}
			if (a->dstaddr){
				inet_ntop(AF_INET, &((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr, buf, 100);
				printf("\tDestination Address: %s\n", buf);
				memset(buf, 0, 100);
			}
			break;

		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			if (a->addr) {
				inet_ntop(AF_INET6, &((struct sockaddr_in*)a->addr)->sin_addr.s_addr, buf, 100);
				printf("\tAddress: %s\n", buf);
				memset(buf, 0, 100);
			}
			break;

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}

#undef main
int main(int argc, char** argv){
    printf("STARTED\n");

    pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm *ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;

#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}
    
    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
	
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }
    
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);
    
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
	
    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	ifprint(d);
    
	/* Open the adapter */
	if (d == NULL || (adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
    
    printf("\nlistening on %s...\n", d->description);
	
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
	
	/* Retrieve the packets */
	while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){
		
		if(res == 0)
			/* Timeout elapsed */
			continue;
		
		/* convert the timestamp to readable format */
		local_tv_sec = header->ts.tv_sec;
		ltime=localtime(&local_tv_sec);
		strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
		
		printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	}
	
	if(res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	
   pcap_close(adhandle);  
   return 0;
}
