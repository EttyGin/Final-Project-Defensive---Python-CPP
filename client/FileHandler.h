/*
This file contains functions that handle files in the program.
Contains a reference to the current client to easily access its features
 */
#pragma once

#include <cryptlib.h>
#include <iostream>
#include <fstream>
#include "Client.h"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include "AESWrapper.h"

class FileHandler
{
private:
	Client *client;
	char *fname = new char[NAME_MAX_SIZE];

public:
	FileHandler(Client* c);
	void setFname(char *);
	char *getFname();
	void readTransfer();
	void readMe();
	void createMe();
	bool fileExist(string);
	void savePrivateKey();
	std::vector<uint8_t> readBinFile();
};