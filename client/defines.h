/*
This file contains all the constants in the program
*/
#pragma once
#define VERSION 3
#define ME_FILE "me.info"
#define TRANSFER_FILE "transfer.info"
#define PRIV_FILE "priv.key"
#define PORT_MAX_SIZE 10
#define IP_MAX_SIZE 20
#define NAME_MAX_SIZE 255
#define PAYLOAD_SIZE_SIZE 4
#define CONTENT_SIZE_SIZE 4
#define CODE_SIZE 2
#define PACK_SIZE 2
#define VERSION_SIZE 1
#define ID_SIZE 16
#define PRIV_KEY_MAX_SIZE 1024
#define STR_ID_MAX_SIZE 64

#define REGIST_CODE 1025
#define RSA_CODE 1026
#define RECONNECT_CODE 1027
#define SEND_FILE_CODE 1028
#define VALID_CRC_CODE 1029
#define INVALID_CRC_CODE 1030
#define END_CODE 1031

#define REGIST_SUCCEED 1600
#define REGIST_FAILED 1601
#define RSA_SUCCESS 1602
#define CRC_VALID 1603
#define CONFIRM_RESP 1604
#define RECONNECT_SUCCEED 1605
#define RECONNECT_FAILED 1606
#define GENERIC_ERROR 1607

/*
I added the colors to make it easier for me
to follow the sequence of the program
*/
#define RESP_S "\033[32m" //green
#define RESP_E "\033[0m" //green
#define ERROR_S "\033[31m" //red
#define ERROR_E "\033[0m" //red
#define REQ_S "\033[33m" //yellow
#define REQ_E "\033[0m" //yellow


