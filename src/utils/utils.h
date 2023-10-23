#pragma once

#pragma comment(lib, "Ws2_32.lib")

#include"xquic.h"
#include"xqc_errno.h"
#include"xquic_typedef.h"
#include"xqc_http3.h"

#include"event.h"
#include <cstdlib>
#include<errors.h>
#include<filesystem>
#include <cstring>
#include <cerrno>
#include<inttypes.h>
#include<iostream>
#include<List>
#include<vector>
#include<Windows.h>
#include<io.h>
#include<random>
#include<chrono>
#include<direct.h>
#include<sys/types.h> 
#include<sys/stat.h>
#include<fcntl.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include<stdio.h>


#define XQC_DEMO_INTERFACE_MAX_LEN 64
#define XQC_DEMO_MAX_PATH_COUNT    8
#define MAX_HEADER_KEY_LEN 128
#define MAX_HEADER_VALUE_LEN 4096
