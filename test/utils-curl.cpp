#include <string>
#include <iostream>
#include <memory>
#include <cstdio>

#include <boost/program_options.hpp>
#include <curl/curl.h>

#include "its/pki-its-debug.hh"
#include "its/utils.hh"

#include "utils-curl.hh"
#include "pki-its-report.hh"


size_t
curl_write_data(void *contents, size_t size, size_t nmemb, void *data)
{
	DEBUG_STREAM_CALLED;

	size_t realsize = size * nmemb;
	struct curl_url_data *url_data = (struct curl_url_data *)data;

	url_data->data = (char *)realloc(url_data->data, url_data->size + realsize + 1);
	if(url_data->data == NULL) {
		ERROR_STREAM << "Not enough memory (realloc URL data returned NULL)" << std::endl;
		return 0;
	}

	memcpy(&(url_data->data[url_data->size]), contents, realsize);
	url_data->size += realsize;
	url_data->data[url_data->size] = '\0';

	DEBUG_STREAM << "Write Data returns size " << realsize << std::endl;
	DEBUG_STREAM_RETURNS_OK;
	return realsize;
}


bool
Curl_Send(const std::string &url, const std::string &report_url, const std::string &entity, OCTETSTRING &request, OCTETSTRING &response)
{
	DEBUG_STREAM_CALLED;

	ItsPkiReport report;	
	std::string report_line = "";
	
	CURLcode res = CURLE_HTTP_POST_ERROR;
	struct curl_url_data url_data;
	struct curl_slist *headers = NULL;
	const unsigned char *req = (const unsigned char *)request;
	long req_sz = request.lengthof();

	url_data.size = 0;
	url_data.data = (char *)malloc(4096); /* reasonable size initial buffer */
	if(NULL == url_data.data) {
                ERROR_STREAM << "Memory allocation error" << std::endl;
		return false;
	}
	url_data.data[0] = '\0';

	curl_global_init(CURL_GLOBAL_NOTHING);
	CURL *curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_data);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &url_data);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, req_sz);

		headers = curl_slist_append(headers, "Content-Type: application/x-its-request");
		if (headers == NULL)   {
		    ERROR_STREAM << "CURL: failed to prepare headers" << std::endl;
		    return false;
		}

		res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		if (res != CURLE_OK)   {
			ERROR_STREAM << "curl_easy_setopt(HTTP HEADERS) failed (error=" << res << "): " << curl_easy_strerror(res) << std::endl;
		}
		else   {
			report.before();
			res = curl_easy_perform(curl);
			report.after();
			
			if(res != CURLE_OK)
				ERROR_STREAM << "curl_easy_perform() failed (error=" << res << "): " << curl_easy_strerror(res) << std::endl;
			
			response = OCTETSTRING(url_data.size, (unsigned char *)(url_data.data));
			dump_ttcn_object(response, "Curl response: ");

			report.buildRecord(entity, res == CURLE_OK, report_line);
#ifdef REPORT_PRINT_RECORD
        		CURL_STREAM << report_line << std::endl;
#endif
		}

        	curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();

	if (!report_url.empty() && !report_line.empty())
		if (!report.sendRecord(report_url, report_line))
			ERROR_STREAM << "Failed to send report record" << std::endl;
    	
	free(url_data.data);

	if (res != CURLE_OK)
		return false;

	DEBUG_STREAM_RETURNS_OK;
	return true;
}

