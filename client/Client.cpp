#include "Client.h"
#include "FileHandler.h"



extern unsigned long memcrc(char* b, size_t n);

//Handles the client activity
Client::Client() : io_context(), s(io_context) {
	setOk(1);
	FileHandler *f = new FileHandler(this);
	f->readTransfer();

	if (!isOk()) { delete[] f; return; }
	tcp::resolver resolver(io_context);
	boost::asio::connect(s, resolver.resolve(ip, port));
	cout << "Connect to server" << endl;
	
	if (!f->fileExist(ME_FILE)) {
		cout << "me.info does not exist, regist" << endl;
		regist();
	}
	else {
		cout << "me.info file exists, reconnect" << endl;
		reconnect();
	}
	if (!isOk()) { delete[] f; return;	}

	vector<uint8_t> fileContent = f->readBinFile();
	if (!isOk()) { delete[] f; return; }


	string encrypted_file = encryptContent(fileContent);
	calcCrc(fileContent, fileContent.size());
	handleFileSending(encrypted_file, f->getFname());
	
	cout << "Finished!!!! exiting..." << endl;
	delete[] f;
}

void Client::setPort(char *p) {
	port = p;
}
void Client::setIp(char *i) {
	ip = i;
}
void Client::setCname(char *name) {
	cname = name;
}
void Client::setId(boost::uuids::uuid i) {
	memcpy(id.data, i.data, ID_SIZE);
}
void Client::setPrivateKey(string key) {
	privateKey = key;
}
void Client::setPublicKey(string key) {
	publicKey = key;
}
void Client::setAESkey(string key) {
	AESkey = key;
}
void Client::setCrc(uint32_t c) {
	crc = c;
}
void Client::setOk(bool o) {
	ok = o;
}

char* Client::getCname() {
	return cname;
}
boost::uuids::uuid Client::getId() {
	return id;
}
string Client::getPrivateKey() {
	return privateKey;
}
uint32_t Client::getCrc() {
	return crc;
}
uint32_t Client::isOk() {
	return ok;
}

//Handles the registration stage, include create keys and send RSA key
void Client::regist() {
	sendRegistReq();
	if (!isOk()) return;

	getRegistResp();
	if (!isOk()) return;

	FileHandler(this).createMe();
	if (!isOk()) return;

	createRSA();
	FileHandler(this).savePrivateKey();
	if (!isOk()) return;

	sendPublicKeyReq();

	getPublicKeyResp();

}

//Handles the reconnecting stage
void Client::reconnect() {
	FileHandler(this).readMe();
	if (!isOk()) return;

	sendReconnectReq();
	getReconnectResp();
}

//Creates RSA keys by RSAPrivateWrapper class
void Client::createRSA() {
	
	RSAPrivateWrapper* priv_key = new RSAPrivateWrapper();
	
	privateKey = priv_key->getPrivateKey();
	cout << "my private key: " << endl << Base64Wrapper().encode(privateKey) << endl;
	
	publicKey = priv_key->getPublicKey();
	cout << "my public key: " << endl << Base64Wrapper().encode(publicKey) << endl;
}

string Client::encryptContent(vector<uint8_t> content)
{
	string encrypted = AESWrapper((unsigned char *)AESkey.c_str(), AESkey.length()).encrypt(reinterpret_cast<char *>(content.data()), content.size());
	cout << "file content is encypted by aes key\n";
	return encrypted;
}

//Sends the encrypted file content to the server
void Client::sendFileReq(string content, char *fname) {
	std::vector<uint8_t> contentToSend(content.begin(), content.end());

	uint32_t content_size = content.length();
	uint32_t orig_size = content.length(); /*TODO: fill it right*/
	uint16_t pack_num = 1;
	uint16_t total = 1;
	Header file;
	memset(&file, 0, sizeof(file));
	file.version = VERSION;
	file.code = SEND_FILE_CODE;
	std::memcpy(file.clientId.data, id.data, ID_SIZE);
	file.payloadSize = NAME_MAX_SIZE + CONTENT_SIZE_SIZE + PACK_SIZE + PACK_SIZE + CONTENT_SIZE_SIZE + content.length();
	boost::asio::write(s, boost::asio::buffer(&file, sizeof(file))); //header
	boost::asio::write(s, boost::asio::buffer(&content_size, CONTENT_SIZE_SIZE)); // content size
	boost::asio::write(s, boost::asio::buffer(&orig_size, CONTENT_SIZE_SIZE)); // orig file
	boost::asio::write(s, boost::asio::buffer(&pack_num, PACK_SIZE)); // pack number
	boost::asio::write(s, boost::asio::buffer(&total, PACK_SIZE)); //total packets
	boost::asio::write(s, boost::asio::buffer(fname, NAME_MAX_SIZE)); //file name
	boost::asio::write(s, boost::asio::buffer(contentToSend));
	cout << REQ_S << "file" << fname << " sent" << REQ_E << endl;

}

//Sends a response regarding the result of the CRC calculation, according to the code
void Client::sendCrcReq(char *fname, int code)
{
	Header crc;
	memset(&crc, 0, sizeof(crc));
	memcpy(crc.clientId.data, id.data, ID_SIZE);

	string res = "valid crc";
	if (code == INVALID_CRC_CODE)
		res = "invalid crc";
	if (code == END_CODE)
		res = "end";
	res = res + " response sent";

	crc.code = code;
	crc.version = VERSION;
	crc.payloadSize = NAME_MAX_SIZE;

	boost::asio::write(s, boost::asio::buffer(&crc, sizeof(crc)));
	boost::asio::write(s, boost::asio::buffer(fname, crc.payloadSize));

	cout << REQ_S << res << REQ_E << endl;
}


void Client::calcCrc(vector<uint8_t> content, size_t csize){
	//size_t size_c = char_traits<char>::length(reinterpret_cast<char*>(content.data()));
	crc = memcrc(reinterpret_cast<char*>(content.data()), csize);

	cout << "crc of the file is: " << crc << endl;
}

// Handles the sending encrypted file to the server
void Client::handleFileSending(string EncryptedFile, char *fname)
{
	int i = 0;
	while (i < 3) {
		sendFileReq(EncryptedFile, fname);//send the encrypted file to server
		if (getFileResp(EncryptedFile, fname)) { //get the response from server and compare the received crc to the client's crc
			//the crc is equal, so send a right_crc request
			sendCrcReq(fname, VALID_CRC_CODE);
			getCrcResp(fname, true);
			return;
		}
		if (isOk()) // not equals but there is no error
		{
			//get confirmation to the response and come into the loop again
			i++;
			sendCrcReq(fname, INVALID_CRC_CODE);
			getCrcResp(fname, false);
			if (!isOk()) 
				return;
		}
		else 
			return;
	}
	//Calculation error 3 times in a row, exits
	sendCrcReq(fname, END_CODE);
	getEndResp();
}

//Sends registration request to the server
void Client::sendRegistReq() {
	Header regist;
	memset(&regist, 0, sizeof(regist));
	regist.version = VERSION;
	regist.code = REGIST_CODE;
	regist.payloadSize = NAME_MAX_SIZE;

	boost::asio::write(s, boost::asio::buffer(&regist, sizeof(regist)));
	boost::asio::write(s, boost::asio::buffer(cname, regist.payloadSize));

	cout << REQ_S <<"regist request sent" << REQ_E <<endl;

}
/*
void Client::sendPublKey() {
	//this function send a public key request to the server
	Header rsa;
	memset(&rsa, 0, sizeof(rsa));
	rsa.version = VERSION;
	rsa.code = RSA_CODE;
	std::memcpy(rsa.clientId.data, id.data, ID_SIZE);
	rsa.payloadSize = publicKey.length() + NAME_MAX_SIZE;

	boost::asio::write(s, boost::asio::buffer(&rsa, sizeof(rsa)));
	boost::asio::write(s, boost::asio::buffer(cname, NAME_MAX_SIZE));
	boost::asio::write(s, boost::asio::buffer(publicKey, publicKey.length()));
	
	cout << REQ_S << "public key request sent" << REQ_E << endl;
}
*/
void Client::sendPublicKeyReq() {
	//this function send a public key request to the server
	Header rsa;
	memset(&rsa, 0, sizeof(rsa));
	rsa.version = VERSION;
	rsa.code = RSA_CODE;
	memcpy(rsa.clientId.data, id.data, ID_SIZE);
	rsa.payloadSize = publicKey.length() + NAME_MAX_SIZE;
	boost::asio::write(s, boost::asio::buffer(&rsa, sizeof(rsa)));
	boost::asio::write(s, boost::asio::buffer(cname, NAME_MAX_SIZE));
	boost::asio::write(s, boost::asio::buffer(publicKey, publicKey.length()));
	cout << REQ_S << "public key request sent" << REQ_E << endl;
}

void Client::sendReconnectReq() {
	//this function send a reconnect request to server
	Header reconnect;
	memset(&reconnect, 0, sizeof(reconnect));
	memcpy(reconnect.clientId.data, id.data, ID_SIZE);

	reconnect.code = RECONNECT_CODE;
	reconnect.version = VERSION;
	reconnect.payloadSize = NAME_MAX_SIZE;

	boost::asio::write(s, boost::asio::buffer(&reconnect, sizeof(reconnect)));
	boost::asio::write(s, boost::asio::buffer(cname, reconnect.payloadSize));
	cout << REQ_S << "reconnection request sent" << REQ_E << endl;
}

//Gets registration response from the server and parse it
void Client::getRegistResp() {
	int i = 0;
	while (i < 3) {
		Response response;
		boost::asio::read(s, boost::asio::buffer(&response, sizeof(response)));

		cout << RESP_S << "Received response:" << RESP_E << " Version: " << static_cast<int>(response.version) << " Code: " << static_cast<int>(response.code) << " Payload Size: " << response.payloadSize << endl;

		if (response.code == REGIST_SUCCEED) {
			boost::asio::read(s, boost::asio::buffer(id.data, response.payloadSize));
			cout << "succseed to regist!! Received UUID: " << to_string(id) << endl;
			return;
		}
		if (response.code == REGIST_FAILED) {
			cout << ERROR_S << "Error: in registration" << ERROR_E << endl;
			setOk(0);
			return;
		}
		if (response.code == GENERIC_ERROR) {//if there was error, try to send again, until 3 times
			i++;
			if (i < 3)
				sendRegistReq();
		}
		else {
			setOk(0);
			cout << ERROR_S <<"Error: cannot recognize the code" <<  ERROR_E << endl;
			return;
		}
	}
	//error 3 times, exits
	setOk(0);
	cout << ERROR_S << "Error: third attempt failed. Can't register" << ERROR_E << endl;
}

//Receives the id and aes key, and decrypt the aes key by the private rsa key
void Client::getAESkeyResp(int payloadSize) {
	boost::uuids::uuid receivedId;
	boost::asio::read(s, boost::asio::buffer(receivedId.data, ID_SIZE));//get the id

	if (to_string(receivedId) != to_string(id)) {
		cout << ERROR_S << "Error: wrong client id" << ERROR_E << endl;
		setOk(0);
		return;
	}

	int keyLen = payloadSize - ID_SIZE;
	char* cipher_aes_key = new char[keyLen];
	boost::asio::read(s, boost::asio::buffer(cipher_aes_key, keyLen));//get the aes key
	AESkey = RSAPrivateWrapper(privateKey).decrypt(cipher_aes_key, keyLen);//decrypt the aes key
	cout << "aes key decrypted by the private RSA key. decrypted aes key is:" << endl << Base64Wrapper().encode(AESkey) << endl;
	delete[] cipher_aes_key;
}

//Gets response from the server for public key sending request and parse it
void Client::getPublicKeyResp() {
	int i = 0;
	while (i < 3) {
		Response response;
		boost::asio::read(s, boost::asio::buffer(&response, sizeof(response)));

		cout << RESP_S << "Received response:" << RESP_E << " Version: " << static_cast<int>(response.version) << " Code: " << static_cast<int>(response.code) << " Payload Size: " << response.payloadSize << endl;

		if (response.code == RSA_SUCCESS) {//if the sending seccseed, get the payload - aes key
			cout << "received aes key!!" << endl;
			getAESkeyResp(response.payloadSize);
			return;
		}
		if (response.code == GENERIC_ERROR) {//if there was error, try to send again, until 3 times
			i++;
			if (i < 3)
				sendPublicKeyReq();
		}
		else {
			setOk(0);
			cout << ERROR_S << "Error: cannor recognize the code" << ERROR_E << endl;
			return;
		}
	}
	//error 3 times, exits
	setOk(0);
	cout << ERROR_S << "Error: third attempt failed. Can't register" << ERROR_E << endl;
}

//Gets reconaction response from the server and parse it
void Client::getReconnectResp() {
	int i = 0;
	while (i < 3) {
		Response response;
		boost::asio::read(s, boost::asio::buffer(&response, sizeof(response)));

		cout << RESP_S << "Received response:" << RESP_E << " Version: " << static_cast<int>(response.version) << " Code: " << static_cast<int>(response.code) << " Payload Size: " << response.payloadSize << endl;

		if (response.code == RECONNECT_FAILED) {
			boost::uuids::uuid receivedId;
			boost::asio::read(s, boost::asio::buffer(receivedId.data, ID_SIZE));

			if (to_string(receivedId) != to_string(id)) {
				cout << ERROR_S << "Error: wrong client id" << ERROR_E << endl;
				setOk(0);
				return;
			}

			//if the reconnection failed, try to regist
			regist();
			return;
		}
		if (response.code == RECONNECT_SUCCEED) {
			//if the reconnection succseed, the payload will be aes key
			cout << "succseed to reconnect!!" << endl;
			getAESkeyResp(response.payloadSize);
			return;
		}

		if (response.code == GENERIC_ERROR) {//if there was error, try to send again, until 3 times
			i++;
			sendReconnectReq();
		}
		else {
			setOk(0);
			cout << ERROR_S << "Error: cannor recognize the code" << ERROR_E << endl;
			return;
		}
	}
	//error 3 times, exits
	setOk(0);
	cout << ERROR_S << "Error: third attempt failed. Can't register" << ERROR_E << endl;
}

//Gets response from the server for sendin file and parse it
bool Client::getFileResp(string content, char *fname) { 
	int i = 0;
	while (i < 3) {
		Response response;
		boost::asio::read(s, boost::asio::buffer(&response, sizeof(response)));

		cout << RESP_S << "Received response:" << RESP_E << " Version: " << static_cast<int>(response.version) << " Code: " << static_cast<int>(response.code) << " Payload Size: " << response.payloadSize << endl;

		if (response.code == CRC_VALID) {//if the code is a code of seccess response, get the payload:
			cout << "file sent successfully! crc response received" << endl;

			boost::uuids::uuid receivedId;
			boost::asio::read(s, boost::asio::buffer(receivedId.data, ID_SIZE));

			if (to_string(receivedId) != to_string(id)) {
				cout << ERROR_S << "Error: wrong client id" << ERROR_E << endl;
			}

			std::vector<uint8_t> contentSize(PAYLOAD_SIZE_SIZE); //by bytes
			boost::asio::read(s, boost::asio::buffer(contentSize, PAYLOAD_SIZE_SIZE));
 
			std::vector<uint8_t> fnameBytes(NAME_MAX_SIZE); //by bytes
			boost::asio::read(s, boost::asio::buffer(fnameBytes, NAME_MAX_SIZE));
			char* receFname = new char[NAME_MAX_SIZE];
			std::memcpy(receFname, fnameBytes.data(), NAME_MAX_SIZE);

			if (strcmp(receFname, fname)) {
				cout << ERROR_S << "Error: wrong file name" << ERROR_E << endl;

			}

			delete[] receFname;

			//get the crc and check if it is equal to the crc that the client calculated. return the answer
			uint32_t CKsum;
			boost::asio::read(s, boost::asio::buffer(&CKsum, sizeof(CKsum)));
			return verifyCrc(CKsum);

		}
		if (response.code == GENERIC_ERROR) {//if there was error, try to send again, until 3 times
			i++;
			if (i < 3)
				sendFileReq(content, fname);
		}
		else {
			setOk(0);
			cout << ERROR_S << "Error: cannot recognize the code" << ERROR_E << endl;
		}
		return false;
	}
	//error 3 times, exits
	setOk(0);
	cout << ERROR_S << "Error: third attempt failed. Can't register" << ERROR_E << endl;
}

//Handles receiving a CRC check result message - according to the Boolean value
void Client::getCrcResp(char *fname, bool valid) {
	int i = 0;
	while (i < 3) {
		Response response;
		boost::asio::read(s, boost::asio::buffer(&response, sizeof(response)));

		cout << RESP_S << "Received response:" << RESP_E << " Version: " << static_cast<int>(response.version) << " Code: " << static_cast<int>(response.code) << " Payload Size: " << response.payloadSize << endl;

		if (response.code == CONFIRM_RESP) {
			boost::uuids::uuid receivedId;
			boost::asio::read(s, boost::asio::buffer(receivedId.data, ID_SIZE));
			if (to_string(receivedId) != to_string(id)) {
				cout << ERROR_S << "Error: wrong client id" << ERROR_E << endl;
			}
			return;
		}
		if (response.code == GENERIC_ERROR) {//if there was error, try to send again, until 3 times
			i++;
			if (i < 3)
				if (valid)
					sendCrcReq(fname, VALID_CRC_CODE);
				else
					sendCrcReq(fname, VALID_CRC_CODE);
		}
		else {
			setOk(0);
			cout << ERROR_S << "Error: cannot recognize the code" << ERROR_E << endl;
			return;
		}
	}
	//error 3 times, exits
	setOk(0);
	cout << ERROR_S << "Error: third attempt failed. Can't register" << ERROR_E << endl;
}

// Gets response from the server for sending end request and parse it
void Client::getEndResp()  { 
	int i = 0;
	while (i < 3) {
		Response response;
		boost::asio::read(s, boost::asio::buffer(&response, sizeof(response)));

		cout << RESP_S << "Received response:" << RESP_E << " Version: " << static_cast<int>(response.version) << " Code: " << static_cast<int>(response.code) << " Payload Size: " << response.payloadSize << endl;

		if (response.code == CONFIRM_RESP) {
			boost::uuids::uuid receivedId;
			boost::asio::read(s, boost::asio::buffer(receivedId.data, ID_SIZE));
			if (to_string(receivedId) != to_string(id)) {
				cout << ERROR_S << "Error: wrong client id" << ERROR_E << endl;
			}
			return;
		}
		if (response.code == GENERIC_ERROR) {//if there was error, try to send again, until 3 times
			i++;
			if (i < 3)
				sendRegistReq();
		}
		else {
			setOk(0);
			cout << ERROR_S << "Error: cannot recognize the code" << ERROR_E << endl;
			return;
		}
	}
	//error 3 times, exits
	setOk(0);
	cout << ERROR_S << "Error: third attempt failed. Can't register" << ERROR_E << endl;
}

//Compares the crc that claculated by the client to the crc that received from server
bool Client::verifyCrc(uint32_t receCrc) {
	string res = "";
	if (getCrc() != receCrc)
		res = "not ";

	cout << "crc is " << res << "equal\n";
	return getCrc() == receCrc;
}
