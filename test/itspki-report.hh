#ifndef ITS_PKI_REPORT_HH
#define ITS_PKI_REPORT_HH

#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>
#include <boost/program_options.hpp>

class ItsPkiReport {
private:
	std::string CLASS_NAME = std::string("ItsPkiReport");
	// std::string url;
	std::string last_record;
	struct timeval time_now;
	struct timespec ts_start;
	struct timespec ts_end;
	long sec, nsec;
	struct tm *htm = NULL;
public: 
	// ItsPkiReport(std::string &_url) {url = _url;};
	// ItsPkiReport(const char *_url) { url = std::string(_url);};
	ItsPkiReport() {};
	~ItsPkiReport() {};
	bool before();
	bool after();
	bool getRecord(std::string &out) {
		if (last_record.empty()) return false;
		out = last_record;
		return true;
	};
	bool buildRecord(const std::string &, bool);
	bool buildRecord(const std::string &, bool, std::string &);
	bool sendRecord(const std::string &, std::string &);
};

#endif // ifndef ITS_PKI_REPORT_HH
