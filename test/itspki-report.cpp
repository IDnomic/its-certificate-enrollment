#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>
#include <boost/program_options.hpp>
#include <memory>
 
#include <openssl/ec.h>
#include <openssl/err.h>
#include "openssl/conf.h"
#include "openssl/err.h"
#include "openssl/engine.h"
#include "openssl/ssl.h"

#include <curl/curl.h>

#include "TTCN3.hh"
#include "EtsiTs103097Module.hh"
#include "EtsiTs102941MessagesCa.hh"

#include "its/itspki-debug.hh"

#include "utils-curl.hh"
#include "itspki-report.hh"


bool
ItsPkiReport::before()
{
	DEBUGC_STREAM_CALLED;

	gettimeofday(&time_now, NULL);
	htm = gmtime(&time_now.tv_sec);
	clock_gettime(CLOCK_REALTIME, &ts_start);

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiReport::after()
{
	DEBUGC_STREAM_CALLED;

	clock_gettime(CLOCK_REALTIME, &ts_end);

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiReport::buildRecord(const std::string &id, bool result)
{
	DEBUGC_STREAM_CALLED;
        
	char str[0x180];
	long sec = ts_end.tv_sec - ts_start.tv_sec;
	long nsec = ts_end.tv_nsec - ts_start.tv_nsec;
	if (nsec < 0)
		sec--, nsec = 1000000000l - ts_start.tv_nsec + ts_end.tv_nsec;
  
	snprintf(str, sizeof(str), "{\"timestamp\":\"%4i-%02i-%02iT%02i:%02i:%02i.%03liZ\",\"latency\":%li.%03li,\"its\":\"%s\",\"status\":\"%s\"}",
			htm->tm_year + 1900, htm->tm_mon + 1, htm->tm_mday, htm->tm_hour, htm->tm_min, htm->tm_sec, time_now.tv_usec/1000l,
			sec, nsec/1000000l,
			id.c_str(), 
			result ? "OK" : "KO");

	last_record = std::string(str);

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiReport::buildRecord(const std::string &id, bool result, std::string &record)
{
	if (!buildRecord(id, result)) 
		return false;
	if (!getRecord(record))
		return false;
	return true;
}


bool
ItsPkiReport::sendRecord(const std::string &url, std::string &record)
{
	if (url.empty())
		return true;

	DEBUGC_STREAM_CALLED;

	curl_global_init(CURL_GLOBAL_NOTHING);
	CURL *curl_es = curl_easy_init();
	if( curl_es == NULL) {
		ERROR_STREAMC << "Curl init error" << std::endl;
		return false;
	}

	std::cout << "URL: " << url << "; Record: " << record << std::endl;
	
	struct curl_url_data es_url_data;
	es_url_data.size = 0;
	es_url_data.data = (char *)calloc(1, 4096); /* reasonable size initial buffer */

	curl_easy_setopt(curl_es, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl_es, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	curl_easy_setopt(curl_es, CURLOPT_WRITEFUNCTION, curl_write_data);
	curl_easy_setopt(curl_es, CURLOPT_WRITEDATA, &es_url_data);
	curl_easy_setopt(curl_es, CURLOPT_POSTFIELDS, record.c_str());
	curl_easy_setopt(curl_es, CURLOPT_POSTFIELDSIZE, record.length());

	struct curl_slist *es_headers = curl_slist_append(NULL, "Content-Type: application/json");
	curl_easy_setopt(curl_es, CURLOPT_HTTPHEADER, es_headers);

	CURLcode es_res = curl_easy_perform(curl_es);
	if (es_res != CURLE_OK)   {
		ERROR_STREAMC << "failed to send ES log (error=" << es_res << "): " << curl_easy_strerror(es_res) << std::endl;
		if (es_url_data.size)
			ERROR_STREAMC << "error ES payload: " << es_url_data.data << std::endl;
	}
	else   {
		std::cout << "SendRecord OK" << std::endl << "Payload: " << es_url_data.data << std::endl;
	}

	free(es_url_data.data);
	curl_slist_free_all(es_headers);
	curl_easy_cleanup(curl_es);
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}
