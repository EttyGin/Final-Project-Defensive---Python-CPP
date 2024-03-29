#include "FileHandler.h"

FileHandler::FileHandler(Client *c) {
	this->client = c;
}

char *FileHandler::getFname() {
	return fname;
}
void FileHandler::setFname(char *name) {
	fname = name;
}
/*
* Reads the data from "transfer.info" file: ip, port, client name
* and path to the binary file
*/
void FileHandler::readTransfer()
{
	try {
		ifstream transferFile;
		transferFile.open(TRANSFER_FILE, ios::in);

		if (!transferFile.is_open()) {
			std::cerr << "Error: cannot open transfer.info" << std::endl;
		}
		char* port = new char[PORT_MAX_SIZE];
		char* ip = new char[IP_MAX_SIZE];
		char* cname = new char[NAME_MAX_SIZE];
		//FileHandler *file = new FileHandler();

		transferFile.getline((char*)ip, IP_MAX_SIZE, ':');
		transferFile.getline(port, PORT_MAX_SIZE);
		transferFile.getline(cname, NAME_MAX_SIZE - 1);
		transferFile.getline(fname, NAME_MAX_SIZE - 1);
		size_t cnameLen = strlen(cname);
		size_t fnameLen = strlen(fname);
		cname[cnameLen] = '\0';
		fname[fnameLen] = '\0';

		// Pad the buffer with null bytes
		if (cnameLen < NAME_MAX_SIZE) {
			std::memset(cname + cnameLen + 1, '\0', NAME_MAX_SIZE - cnameLen - 1);
		}
		if (fnameLen < NAME_MAX_SIZE) {
			std::memset(fname + fnameLen + 1, '\0', NAME_MAX_SIZE - fnameLen - 1);
		}
		client->setIp(ip);
		client->setCname(cname);
		client->setPort(port);
		setFname(fname);

		cout << "transfer.info content is:\n" << "ip: " << ip << endl << port << endl << cname << endl << fname << endl;
		transferFile.close();
		return;
	}
	catch (...) {

		cout << "transfer.info is not exist." << endl;
		client->setOk(0);
		return;
	}
}
/*
Reads the information for reconnecting from "me.info" file and "priv.key' file
*/
void FileHandler::readMe() {
	
	char *privKeyWarp = new char[PRIV_KEY_MAX_SIZE];
	char *name = new char[NAME_MAX_SIZE];
	char *uuid = new char[STR_ID_MAX_SIZE];

	//read me.info
	try {

		ifstream meFile;
		meFile.open(ME_FILE, ios::in);
		if (meFile.is_open())
			cout << "opened file me" << endl;
		else cout << "didn't open file me" << endl;

		meFile.getline(name, NAME_MAX_SIZE);
		meFile.getline(uuid, STR_ID_MAX_SIZE);
		meFile.close();
		cout << name << ": " << uuid << endl;

		if (strcmp(name, client->getCname())) {
			cout << "The client name does not match in me.info and transfer.info files." << endl;
			client->setOk(0);
			return;
		}
	}
	catch (...) { 
		cout << "error in read me file" << endl;
		client->setOk(0);
		return;
	}

	try {
		// Parse the hexadecimal UUID string into a UUID object
		boost::uuids::string_generator gen;
		boost::uuids::uuid id = gen(uuid);
		client->setId(id);
	}
	catch (...) {
		std::cout << "Error parsing UUID " << std::endl;
	}

	//read priv.key
	try {
		ifstream privFile;
		privFile.open(PRIV_FILE, ios::in);
		privFile.read(privKeyWarp, PRIV_KEY_MAX_SIZE);//read the private key
		client->setPrivateKey(Base64Wrapper().decode(privKeyWarp));
		privFile.close();
	}
	catch (...) { 
		cout << "Error in read priv_file" << endl;
		client->setOk(0);
		return;
	}

	delete[] privKeyWarp;
	delete[] name;
	delete[] uuid;
}
/*
Checks whether there is a file named as the parameter name
Returns an answer that matches
*/
bool FileHandler::fileExist(string name) {

	ifstream file;
	file.open(name, ios::in | ios::_Nocreate);
	if (!file.is_open())
		return false;

	file.close();
	return true;

}
/*
* Creates me.info file and saves the name and id
*/
void FileHandler::createMe() {
	string uuidStr = boost::uuids::to_string(client->getId());
	try {
		ofstream file(ME_FILE);
		file << client->getCname() << endl;
		file << uuidStr << endl;
		file.close();
	}
	catch (...) { 
		cout << "Error: cannot create me.info file"; 
		client->setOk(0);
	}

	cout << "me.info file content: " << client->getCname() << endl << uuidStr << endl;

}

/*
* saves the private key to me.info file and priv.key file
*/
void FileHandler::savePrivateKey() {
	string privKeyWarp = Base64Wrapper().encode(client->getPrivateKey());

	try {
		ofstream meFile;
		meFile.open(ME_FILE, ios::out | ios::app);
		meFile << privKeyWarp << endl;
		meFile.close();
	}
	catch (...) {
		cout << "Error: cannot open me file";
		client->setOk(0);
		return;
	}

	try {
		ofstream privFile(PRIV_FILE);
		privFile << privKeyWarp << endl;
		privFile.close();
	}
	catch (...) { 
		cout << "Error: cannor create priv file"; 
		client->setOk(0);
	}

	cout << "private key saved in me.info and in priv.key" << endl;
}

/*
* Reads the content from the binary file
* Returns the content
*/
std::vector<uint8_t> FileHandler::readBinFile() {
	std::streampos fileSize;

	try {
		ifstream binFile;
		binFile.open(getFname(), ios::in | ios::binary);
		binFile.seekg(0, std::ios::end);
		fileSize = binFile.tellg();
		binFile.seekg(0, std::ios::beg);

		std::vector<uint8_t> content(fileSize);
		binFile.read(reinterpret_cast<char*>(content.data()), fileSize); //read the file in binary format
		binFile.close();

		cout << "File content is: " << endl << content.data() << endl;
		return content;
	}
	catch (...) { 
		cout << "Error: cannot read the binary file" << endl;
		client->setOk(0);
		return vector<uint8_t>();
	}
}
