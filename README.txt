------ Tool description -------------------------------------------
This tool captures TCP and UDP packages of a specific
interface on a machine using the pcap lib. The capture 
is interface specific and the user can scan the various 
interfaces availabled to be scanned using

    sudo ./pcap_ex -s

Afterwards by running 

    sudo ./pcap_ex -i eth0 
    sudo ./pcap_ex -i enp0s3
    ...
the tool asks for any desired filtering options and then 
proceeds with the capture of packages on the specific interface
-------------------------------------------------------------------


------ Software description ---------------------------------------
The code uses the getopt function for unistd.h to parse the 
command line flags and arguments. Please note that the filtering
is implemented via the command line with I/O operations using
printf/scanf because the flag implementation was comple
(An other case clause should be added for the -f flag but the 
function for capture has already been called by the -i case.)

The appropriate case clause calls the function for capture
either for live capturing or file reading. Both ways lead to
the same decode function for the TCP and UDP functions respectively.
A package handler is implemented in order to accept incoming 
packets. The handler decides the protocol used for the packet
delivery (NOT THE HIGHER PROTOCOLS e.g. TCP via HTTP) and calls
the appropriate decode function while respecting the protocol filter
applied. The decode function parses the packet and get its info.
For the calculation of the header's size and for accessing the 
packet's info, the ETHERNET header size is taken into account
because it oversits the sent packages header.
-------------------------------------------------------------------


------ Retransimitted Packages ------------------------------------
I didnt implement the detection of the Retransimitted packages 
that happen via TCP protocol because it was complex and I had barely
no time. It is possible though to detect Retransimitted packages by 
checking the sequence number of the last ACK and of the package that 
is transmitted now. 

The detection is not possible for UDP transmissions
-------------------------------------------------------------------


------ Usage & Compilation Specifications -------------------------

--> Compile and produce the executable by running

    make
    
    in the source code directory

--> Run for live capturing:

    sudo ./pcap_ex -i eth0
    
    sudo is important because admin rights are required 
    for monitoring of an interface.

--> Run for file capturing

    sudo ./pcap_ex -r test.pcap


Note: gcc says the pcap_lookupdev() is deprecated, nothing to worry
at this level of development
-------------------------------------------------------------------