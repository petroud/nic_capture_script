#include <stdio.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h> 
#include <string.h> 
#include <arpa/inet.h> 
#include <net/ethernet.h>
#include <netinet/udp.h>	
#include <netinet/tcp.h>	
#include <netinet/ip.h>

#define TCP 11
#define UDP 22

int portFilter;
int transmFilter;

pcap_t* packetHandler;


//Used for statistics 
int totalFlows = 0; 
int tcpFlows = 0;
int udpFlows = 0;
int totalReceived = 0;
int totalTCPReceived = 0;
int totalUDPReceived = 0;
int totalTCPbytes = 0;
int totalUDPbytes = 0;

void getFilters(){
    int opt;
    char method[512];

    printf("--> Select one of the following options for filtering:\n");
    printf("--> 1) Port filtering (1-65535)\n");
    printf("--> 2) Transmission filtering (UDP/TCP)\n");
    printf("--> 3) Multifiltering (Port and Transmission method)\n");
    printf("--> 4) No filter\n");
    printf("--> Your selection: ");
    scanf("%d",&opt);
    switch(opt){
        case 1:
            printf("Enter port number (1-65535): ");
            scanf("%d",&portFilter);
            break;
        case 2:
            printf("Enter transmission method(TCP/UDP): ");
            scanf("%s",method);
            if(strcmp(method,"UDP")==0){
                transmFilter = UDP;
            }
            if(strcmp(method,"TCP")==0){
                transmFilter = TCP;
            }
            break;
        case 3:
            printf("Enter port number (1-65535): ");
            scanf("%d",&portFilter);
            printf("Enter transmission method(TCP/UDP): ");
            scanf("%s",method);
            if(strcmp(method,"UDP")==0){
                transmFilter = UDP;
            }
            if(strcmp(method,"TCP")==0){
                transmFilter = TCP;
            }
            break;
        case 4:
            break;
        default: 
            printf("Invalid option [%d] ...\n", opt);
            break;
    }
}

int scanInterfaces(){

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs;
    int r;

    r = pcap_findalldevs(&devs, errbuf);
    if (r) {
        return -1;
    }

    printf("--> Available network interfaces on this machine: \n");
    while (devs) {
        printf("\tiface: %s - Description: %s", devs->name, devs->description);
        printf("\n");
        devs = devs->next;
    }

}

void printStats(){

    printf("--> Runtime Statistics \n");
    printf("\t--> Total number of network flows captured: %d\n", totalFlows);
    printf("\t--> Number of TCP network flows captured: %d\n", tcpFlows);
    printf("\t--> Number of UDP network flows captured: %d\n", udpFlows);
    printf("\t--> Total number of packets received: %d\n", totalReceived);
    printf("\t--> Number of TCP packets received: %d\n", totalTCPReceived);
    printf("\t--> Number of UDP packets received: %d\n", totalUDPReceived);
    printf("\t--> Total bytes of TCP packets received: %d\n", totalTCPbytes);
    printf("\t--> Total bytes of UDP packets received: %d\n", totalUDPbytes);
}


void terminateLoop(int sig){
    pcap_breakloop(packetHandler);
    pcap_close(packetHandler);    
}


void decodeTCP(const unsigned char* packet, int size){

    char originIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    unsigned int originPort;
    unsigned int destPort;
    unsigned int headerLength;
    
    struct ip *cleanHeader = (struct ip*)(packet + sizeof(struct ethhdr));
    struct ether_header *ether = (struct ether_header*)packet;

    //Not an IPv4 or IPv6 packet, skip...
    if(ntohs(ether->ether_type) != ETHERTYPE_IP && ntohs(ether->ether_type) != ETHERTYPE_IPV6){
        return;
    }

    unsigned short ethOffset = cleanHeader->ip_hl*4;


    inet_ntop(AF_INET, &(cleanHeader->ip_src), originIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(cleanHeader->ip_dst), destIP, INET_ADDRSTRLEN);


    struct tcphdr *tcpHeader = (struct tcphdr*)(packet + ethOffset + sizeof(struct ethhdr));
    originPort = ntohs(tcpHeader->source);
    destPort = ntohs(tcpHeader->dest);
    headerLength = (unsigned int)tcpHeader->doff*4;

    if(portFilter!=0){
        if(originPort!=portFilter && destPort!=portFilter){
            //Filter applied, nothing to do with this transmission
            return;
        }  
    }

    int headerSize = sizeof(struct ethhdr) + ethOffset + tcpHeader->doff*4;
    int payload = size-headerSize;
    totalTCPbytes += size;

    totalFlows++;
    tcpFlows++;

    printf("Source IP: %s --> Dest IP: %s | Source Port : %u --> Dest Port: %u | Protocol: TCP | Header Length: %d | Payload Length: %d\n", originIP, destIP, originPort, destPort, headerLength, payload);

    /*
    //Write output to file
    FILE *fp = fopen("log.txt","a");
    fprintf(fp, "Source IP: %s --> Dest IP: %s | Source Port : %u --> Dest Port: %u | Protocol: TCP | Header Length: %d | Payload Length: %d\n", originIP, destIP, originPort, destPort, headerLength, payload);
    fclose(fp);
    */
}

void decodeUDP(const unsigned char* packet, int size){

    char originIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    unsigned int originPort;
    unsigned int destPort;
    unsigned int headerLength;
    
    struct ip *cleanHeader = (struct ip*)(packet + sizeof(struct ethhdr));
    struct ether_header *ether = (struct ether_header*)packet;

    //Not an IPv4 or IPv6 packet, skip...
    if(ntohs(ether->ether_type) != ETHERTYPE_IP && ntohs(ether->ether_type) != ETHERTYPE_IPV6){
        return;
    }

    unsigned short ethOffset = cleanHeader->ip_hl*4;


    inet_ntop(AF_INET, &(cleanHeader->ip_src), originIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(cleanHeader->ip_dst), destIP, INET_ADDRSTRLEN);


    struct udphdr *udpHeader = (struct udphdr*)(packet + ethOffset + sizeof(struct ethhdr));
    originPort = ntohs(udpHeader->source);
    destPort = ntohs(udpHeader->dest);
    headerLength = (unsigned int)udpHeader->len;

    if(portFilter!=0){
        if(originPort!=portFilter && destPort!=portFilter){
            //Filter applied, nothing to do with this transmission
            return;
        }  
    }

    int headerSize = sizeof(struct ethhdr) + ethOffset + sizeof(udpHeader);
    int payload = size-headerSize;
    
    totalUDPbytes += size;
    totalFlows++;
    udpFlows++;

    printf("Source IP: %s --> Dest IP: %s | Source Port : %u --> Dest Port: %u | Protocol: UDP | Header Length: %d | Payload Length: %d\n", originIP, destIP, originPort, destPort, headerLength, payload);

    /*
    //Write output to file
    FILE *fp = fopen("log.txt","a");
    fprintf(fp, "Source IP: %s --> Dest IP: %s | Source Port : %u --> Dest Port: %u | Protocol: UDP | Header Length: %d | Payload Length: %d\n", originIP, destIP, originPort, destPort, headerLength, payload);
    fclose(fp);
    */
}

void handlePacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    
    totalReceived++;

    //Add the offset of the ethernet packet header length to get the protocol type at appropriate index
    struct iphdr *cleanHeader = (struct iphdr*)(packet + sizeof(struct ethhdr));

    switch(cleanHeader->protocol){

        case IPPROTO_TCP:
            //Do not capture TCP packages
            if(transmFilter==UDP){
                break;
            }
            totalTCPReceived++;
            decodeTCP(packet, header->caplen);
            break;
        case IPPROTO_UDP:
            //Do not capture UDP packages
            if(transmFilter==TCP){
                break;
            }
            totalUDPReceived++;
            decodeUDP(packet, header->caplen);
            break;
        default:
            break;
    }

}

void captureFile(char* path){
    char errbuf[PCAP_ERRBUF_SIZE];
    int timeout = 10000;

    pcap_t *descr = pcap_open_offline(path, errbuf);

    if(descr!=NULL){
        pcap_loop(descr, -1, handlePacket, NULL);
        printStats();
    }else{
        printf("Error while opening the provided filepath!\n");
    }
}


void monitorNetworkInteface(char* iface){
    getFilters();
    //printf("Port filter is %d\n",portFilter);
    //printf("Transmission Filter is: %d\n", transmFilter);

    char error_buffer[PCAP_ERRBUF_SIZE];
    int timeout = 10000;

    iface = pcap_lookupdev(error_buffer);
    if(iface == NULL){
        printf("Error finding device: %s\n", error_buffer);
        return;
    }
    
    packetHandler = pcap_open_live(iface, BUFSIZ, 0, timeout, error_buffer);

    if(packetHandler == NULL){
        printf("Could not open interface %s... @pcap_open_live()\n", iface);
        return;
    }

    signal(SIGINT, terminateLoop);
	pcap_loop(packetHandler, timeout, handlePacket, NULL);

    printStats();

    return;
}


int main(int argc, char *argv[])
{
    int opt;
    char device[512];
    char path[512];

    remove("log.txt");

    while((opt = getopt(argc,argv,"i:r:sh")) != -1){

        switch(opt){
            case 'h':
                printf("\t-i Network interface name (e.g. eth0).\n");
                printf("\t-r Packet capture file name (e.g. test.pcap).\n");
                printf("\t-f Filter port expression (e.g. port 8080 / transmission UDP/TCP).\n");
                printf("\t-s Scan available interfaces to monitor\n");
                printf("\t-h This help message.\n");
                printf("\tExamples:\n");
                printf("\t ./pcap_ex -i eth0 (saves the packets in log.txt\n");
                printf("\t ./pcap_ex -r test_pcap_5mins.pcap (prints the output in terminal\n");
                printf("\t ./pcap_ex -i eth0 -f \"port 8080\"\n");
                printf("\t ./pcap_ex -i eth0 -f \"transmission UDP\"\n");
                break;
            case 'i':
                //Get the selected interface
                strcpy(device, optarg);
                monitorNetworkInteface(device);
                break;
            case 'r':
                //Read the pcap file
                strcpy(path,optarg);
                captureFile(path);
                break;
            case 's':
                //Scan for available interfaces
                scanInterfaces();
                break;
            default:
                printf("No such option [%d]....\n",optopt);
                break;
        }

    }

    return 0;
	
}