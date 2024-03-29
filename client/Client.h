#pragma once

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <rsa.h>
#include <fstream>
#include <cstdint>
#include <cryptlib.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <boost/asio.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/algorithm/hex.hpp>
#include "defines.h"
#pragma pack(push, 1)

using namespace CryptoPP;
using boost::asio::ip::tcp;
using namespace std;


class Client
{
private:
	char* port = new char[PORT_MAX_SIZE];
	char* ip = new char[IP_MAX_SIZE];
	char* cname = new char[NAME_MAX_SIZE];
	boost::uuids::uuid id;

	string privateKey;
	string publicKey;
	string AESkey;
	uint32_t crc;

	boost::asio::io_context io_context;
	tcp::socket s;

	bool ok;

public:
	Client();
	void setPort(char *);
	void setIp(char *);
	void setCname(char *);
	void setId(boost::uuids::uuid);
	void setPrivateKey(string);
	void setPublicKey(string);
	void setAESkey(string);
	void setCrc(uint32_t);
	void setOk(bool);

	char *getCname();
	boost::uuids::uuid getId();
	string getPrivateKey();
	uint32_t getCrc();
	uint32_t isOk();

	void regist();
	void reconnect();

	void createRSA();
	string encryptContent(std::vector<uint8_t>);
	void calcCrc(std::vector<uint8_t>, size_t);
	void handleFileSending(string, char *);
	bool verifyCrc(uint32_t);

	void sendRegistReq(); ///1025
	void sendPublicKeyReq(); //1026
	void sendReconnectReq(); //1027
	void sendFileReq(string, char *); //1028
	void sendCrcReq(char *, int); //1029|30|1


	void getRegistResp(); //1600|1
	void getAESkeyResp(int); //1602
	void getPublicKeyResp();
	void getReconnectResp(); //1605|6
	bool getFileResp(string , char *); //1603
	void getCrcResp(char *, bool); //1603|4
	void getEndResp();

};

//for sending requests
struct Header {
	boost::uuids::uuid clientId;
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
};

struct Response {
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
};