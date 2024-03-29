#include "Client.h"

int main() {
	int errorCnt = 0;
	bool start = true;

	while (start)
		try {
			Client();
			start = false;

		}
		catch (...) {
			string detail = " - Trying again";
			errorCnt++;
			if (errorCnt == 3) {
				start = false;
				detail = " - Exiting";
			}	
			cout << ERROR_S << "Fatal error: server responsed with an error" << detail << ERROR_E << endl;
		}

}
