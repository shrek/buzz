#include <stdio.h>
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <klee/klee.h>

//remember which obj is being requested
int pendingHttpObj;
//to remember for whom the proxy is fetching the missing obj
int waitingClientIP;
int waitingClientPort;

Link linkParser(char *linksLineStr){
	char *a[3];
	int n=0, i;

	printf("%s\n",linksLineStr);
	a[n]=strtok(linksLineStr, "\t");

	while(a[n] && (n<4))
		a[++n] = strtok(NULL, "\t");

	Link l;
	l.end1.num = atoi(a[0]);
	l.end2.num = atoi(a[1]);

	return l;
}

Node nodeParser(char *nodesLineStr){
	char a[3][10];
	int n=0, i;

	char *token;
	token = strtok(nodesLineStr ,"\t");

	while((token != NULL) && (n<3)){
		strcpy(a[n++], token);
		token = strtok(NULL, "\t");
	}

	Node node;
	strcpy(node.type, a[0]);
	node.index = atoi(a[1]);
	node.port.num = atoi(a[2]);

	return node;
}

void forwardingTablesParser(char *forwardingTablesFileLineStr){
	char a[6][10];
	int n=0, i;

	char *token;
	token = strtok(forwardingTablesFileLineStr ,"\t");

	while((token != NULL) && (n<6)){
		strcpy(a[n++], token);
		token = strtok(NULL, "\t");
	}

	int inPort = atoi(a[1]);
	int srcIP = atoi(a[2]);
	int dstIP = atoi(a[3]);
	int tag = atoi(a[4]);
	int outPort = atoi(a[5]);

	nextHop[inPort][dstIP][tag] = outPort;
}

locatedPacket packetParser(char* pktStr){
	char *a[TRAFFIC_FILE_NO_OF_FIELDS];
	int n=0, i;
 
	a[n]=strtok(pktStr, "\t");

	while(a[n] && (n<TRAFFIC_FILE_NO_OF_FIELDS))
		a[++n] = strtok(NULL, "\t");

	locatedPacket pkt;
	pkt.packet.id = atoi(a[0]);
	pkt.packet.srcIP = atoi(a[1]);
	pkt.packet.dstIP = atoi(a[2]);
	pkt.packet.srcPort = atoi(a[3]);
	pkt.packet.dstPort = atoi(a[4]);
	pkt.packet.proto = atoi(a[5]);
	pkt.packet.isHttp = atoi(a[6]);
	pkt.packet.httpGetObj = atoi(a[7]);
	pkt.packet.httpRespObj = atoi(a[8]);
	pkt.packet.tag = atoi(a[9]);
	pkt.packet.tcpSYN = atoi(a[10]);
	pkt.packet.tcpACK = atoi(a[11]);
	pkt.packet.tcpFIN = atoi(a[12]);
	pkt.packet.connId = atoi(a[13]);
	pkt.packet.fromClient = atoi(a[14]);
	pkt.packet.timeout = atoi(a[15]);
	pkt.packet.dropped = atoi(a[16]);
	pkt.port.num = atoi(a[17]);

	return pkt;
}


locatedPacket firewallProc(int fwIndex, locatedPacket inPkt){
	//first we set the outpacket to be the same as in packet
	locatedPacket outPkt;
	outPkt = inPkt;	

	outPkt.port.num = fwPorts[fwIndex];

	if (((inPkt.packet.dstIP == 1) || (inPkt.packet.dstIP == 0) || (inPkt.packet.dstIP == 2)) && inPkt.packet.dstPort == 22) {
	  printf("dropping packet to: %d\n", inPkt.packet.dstIP);
	  outPkt.packet.dropped = 1;
	  return outPkt;
        }

	printf("not dropping packet to: %d\n", inPkt.packet.dstIP);	
        //default case. should not get here.
        return outPkt;
}

locatedPacket swProc(locatedPacket inPkt){
	locatedPacket outPkt;
	outPkt = inPkt;
	printf("inside swProc(), \n");
	printf("nextHop[%d][%d][%d][%d] = %d\n", inPkt.port.num, inPkt.packet.srcIP, inPkt.packet.dstIP, inPkt.packet.tag, outPkt.port.num);
	
	outPkt.port.num = nextHop[inPkt.port.num][inPkt.packet.dstIP][inPkt.packet.tag];

	printf("outPkt port is %d\n", outPkt.port.num);
	printf("ending swProc()\n");

	return outPkt;
}

void showLocatedPacket(locatedPacket pkt){
  //printf("&&& pkt id:%d, srcIP:%d, dstIP:%d tag:%d, dropped:%d, @port:%d\n", pkt.packet.id, pkt.packet.srcIP, pkt.packet.dstIP, pkt.packet.tag, pkt.packet.dropped, pkt.port.num);
  printf("&&& pkt id:%d, srcIP:%d, dstIP:%d tag:%d, dropped:%d, @port:%d\n", pkt.packet.id, pkt.packet.srcIP, pkt.packet.dstIP, pkt.packet.tag, pkt.packet.dropped, pkt.port.num);  
}

int main(int argc, char *argv[]){

	// FILE *trafficFile = fopen("./testTraffic.dat","r");
    FILE *nodesFile = fopen("nodes1.dat","r");
    FILE *linksFile = fopen("links1.dat","r");
    FILE *forwardingTablesFile = fopen("forwardingTables1.dat","r");

/*
	if (trafficFile == 0){
		printf("Could not open traffic file\n");
		return 1;
	}
*/

	if (nodesFile == 0){
		printf("Could not open nodes file\n");
		return 1;
	} else {
		printf("Opened nodes file\n");	  
	}

	if (linksFile == 0){
		printf("Could not open links file\n");
		return 1;
	} else {
		printf("Opened links file\n");	  	  
	}

	if (forwardingTablesFile == 0){
		printf("Could not open FT file\n");
		return 1;
	} else {
		printf("Opened FT file\n");	  
	}

	int i;
	int j;

	//Reading the links file************************************************
    char *currentPacketStr = NULL;
    char *linksFileLineStr = NULL;
    size_t len = 0;
	
	//ignore the first line
	getline(&linksFileLineStr, &len, linksFile);

	int linksPort[MAX_NO_OF_NETWIDE_PORTS];
	for (i=0; i<MAX_NO_OF_NETWIDE_PORTS; i++)
		linksPort[i] = -1;

	while (getline(&linksFileLineStr, &len, linksFile) != -1){
		Link l = linkParser(linksFileLineStr);
		linksPort[l.end1.num] = l.end2.num;
		linksPort[l.end2.num] = l.end1.num;
	}
	
	//Reading the nodes file************************************************
	int noOfPorts = 0;
	Node portInfo[MAX_NO_OF_NETWIDE_PORTS];//each port corresponds to one line of nodes.dat
	for (i=0; i<MAX_NO_OF_NETWIDE_PORTS; i++){
		portInfo[i].index = -1;
		portInfo[i].port.num = -1;
	}

	int noOfFws = 0;
	for (i=0; i<MAX_NO_OF_FIREWALLS; i++)
		fwPorts[i] = -1;

	int noOfProxies = 0;
	for (i=0; i<MAX_NO_OF_PROXIES; i++)
		proxyPorts[i] = -1;

	int noOfIPSes = 0;
	for (i=0; i<MAX_NO_OF_IPSES; i++)
		ipsPorts[i] = -1;

	int noOfHosts = 0;
	for (i=0; i<MAX_NO_OF_HOSTS; i++)
		hostPorts[i] = -1;

	int noOfSws = 0;
	int swPorts[MAX_NO_OF_SWITCHES][MAX_NO_OF_SWITCH_PORTS];
	int swPortsSeen[MAX_NO_OF_SWITCHES];

	for (i=0; i<MAX_NO_OF_SWITCHES; i++){
		swPortsSeen[i] = 0;
		for (j=0; j<MAX_NO_OF_SWITCH_PORTS; j++)
			swPorts[i][j] = -1;
	}

       	char *nodesFileLineStr = NULL;

	//ignore the first line
	getline(&nodesFileLineStr, &len, nodesFile);

	while (getline(&nodesFileLineStr, &len, nodesFile) != -1){
		Node node = nodeParser(nodesFileLineStr);

		//this is to have all info about each port in one place as in node.dat
		strcpy(portInfo[node.port.num].type, node.type);
		portInfo[node.port.num].index = node.index;
		portInfo[node.port.num].port.num = node.port.num;

		printf("type=%s, index=%d\n", node.type, node.index);

		if (node.type[0] == 'f')
			fwPorts[noOfFws++] = node.port.num;
		if (node.type[0] == 'i')
			ipsPorts[noOfIPSes++] = node.port.num;
		if (node.type[0] == 'p')
			proxyPorts[noOfProxies++] = node.port.num;
		if (node.type[0] == 'h')
			hostPorts[noOfHosts++] = node.port.num;
		if (node.type[0] == 's'){
			swPorts[node.index][swPortsSeen[node.index]++] = node.port.num;
			if (node.index >= noOfSws)
				noOfSws = node.index + 1;
			printf("DEBUG: %d\n", node.index);
		}
	}

	
	printf("fw ports:\n");
	for (i=0; i<noOfFws; i++)
		printf("%d\n", fwPorts[i]);
	
	printf("host ports:\n");
	for (i=0; i<noOfHosts; i++)
		printf("hostport %d\n", hostPorts[i]);
	/*
	printf("sw info:\n");
	for (i=0; i<noOfSws; i++)
		for (j=0; j < swPortsSeen[i]; j++)
			printf("sw %d, port %d: %d\n", i, j, swInfo[i][j]);

	printf("*********printing port info*********\n");
	for (i=0; i<MAX_NO_OF_NETWIDE_PORTS; i++){
		printf("%d %d %s\n",portInfo[i].index, portInfo[i].port.num, portInfo[i].type);
	}
	printf("*********done printing port info*********\n");
	*/

	//Reading the forwarding tables file************************************************
	int k;
	int l;

	for (i=0; i< MAX_NO_OF_NETWIDE_PORTS; i++)
	  for (k=0; k< MAX_NO_OF_NODES; k++)
	    for (l=0; l< MAX_NO_OF_TAGS; l++)
	      nextHop[i][k][l] = -1;

       	char *forwardingTablesFileLineStr = NULL;

	//ignore the first line
	getline(&forwardingTablesFileLineStr, &len, forwardingTablesFile);

	while (getline(&forwardingTablesFileLineStr, &len, forwardingTablesFile) != -1){
		forwardingTablesParser(forwardingTablesFileLineStr);
	}


	printf("!!!!forwarding tables!!!!\n");
	for (i=0; i< MAX_NO_OF_NETWIDE_PORTS; i++)
	  for (k=0; k< MAX_NO_OF_NODES; k++)
	    for (l=0; l< MAX_NO_OF_TAGS; l++)
	      if (nextHop[i][k][l] >= 0)
		printf("inport:%d, srcIP:%d, dstIP:%d, tag:%d:::outport%d\n",i,j,k,l,nextHop[i][k][l]);
	printf("!!!!end of forwarding tables!!!!\n");

	//this is a test to see if an injected packet can follow through the topology
	int injectionPortNo = 0;


//automatic test generation block

	int zz;

	locatedPacket pkt1;
	pkt1.packet.id = 1;
	pkt1.packet.srcIP = 3;
	//pkt1.packet.dstIP = ;
	pkt1.packet.dropped = 0;
	pkt1.packet.tag = 0;
	pkt1.packet.isHttp = 0;
	pkt1.packet.timeout = 0;
	pkt1.packet.dstPort = 22;
	//pkt1.port.num = 11;
	


	//int srcPort_of_pkt1;
	
	//klee_make_symbolic(&dstPort_of_pkt1, sizeof(dstPort_of_pkt1), "pkt1.packet.dstPort");
	//memcpy(&pkt1.packet.dstPort, &dstPort_of_pkt1, sizeof(dstPort_of_pkt1));

	int srcPort_of_pkt1;
	int dstIP_of_pkt1;
	
	klee_make_symbolic(&dstIP_of_pkt1, sizeof(dstIP_of_pkt1), "pkt1.packet.dstIP");
	memcpy(&pkt1.packet.dstIP, &dstIP_of_pkt1, sizeof(dstIP_of_pkt1));

	klee_make_symbolic(&srcPort_of_pkt1, sizeof(srcPort_of_pkt1), "pkt1.packet.srcPort");
	memcpy(&pkt1.port.num, &srcPort_of_pkt1, sizeof(srcPort_of_pkt1));
	
	
	klee_assume( ((0 <= dstIP_of_pkt1) & (dstIP_of_pkt1 <= 3)) == 1  ) ;

	klee_assume(  (((0 <= srcPort_of_pkt1) & (srcPort_of_pkt1 <= 2)) | (srcPort_of_pkt1 == 11)) == 1 ) ;	  

	klee_assume( ((srcPort_of_pkt1==11) & (dstIP_of_pkt1 == 3)) == 0);

	klee_assume( (srcPort_of_pkt1 != dstIP_of_pkt1) == 1);	
	

	//make it happen with at most 4 packets
	for (zz=0; zz<1;zz++)
	{
		locatedPacket pkt;
		if (zz==0)
			pkt = pkt1;
		
		printf("got a packet with ID %d, dst %d\n", pkt.packet.id, pkt.packet.dstIP);
		showLocatedPacket(pkt);

		//move the packet until it arrives its destination or gets dropped
		while ((pkt.port.num != hostPorts[pkt.packet.dstIP]) && (!pkt.packet.dropped)){
			//forward pkt on the link
		  int oldport;
		  oldport = pkt.port.num;
			pkt.port.num = linksPort[pkt.port.num];
			
			showLocatedPacket(pkt);
			printf("packet ID %d got forwarded by a link from %d to %d\n\n", pkt.packet.id, oldport, pkt.port.num);

			if (portInfo[pkt.port.num].type[0] == 's'){
				pkt = swProc(pkt);
				showLocatedPacket(pkt);
				printf("packet ID %d got processed by a switch\n", pkt.packet.id);
			} else {
			       printf("packet ID %d did not get processed by switch\n", pkt.packet.id);			  
			}

			if (portInfo[pkt.port.num].type[0] == 'f'){
			  pkt = firewallProc(0, pkt);
				showLocatedPacket(pkt);
				printf("packet ID %d got processed by a firewall\n", pkt.packet.id);
			}
			
			printf("\n");
		}

		pkt1.packet.dropped = pkt.packet.dropped;
		printf("#############packet fated###################\n");
	}

	klee_assert((pkt1.packet.dstPort == 22) && pkt1.packet.dropped);
	
	return 0;
}
