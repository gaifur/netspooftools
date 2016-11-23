#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>


#include "dhcp.h"
#include "mac.h"

static volatile unsigned keepRunning = 1;

static void intHandler() {
  keepRunning = 0;
}

int main(int argc, char** argv) {
	raw_iface_t iface;
	int fd;
	ipaddr_t myIp;

	
}
