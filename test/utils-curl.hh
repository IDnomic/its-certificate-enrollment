#ifndef UTILS_CURL_HH
#define UTILS_CURL_HH

#include <string>
#include <iostream>
#include <memory>

enum CURL_CONTENT_TYPE {X_ITS_REQUEST=0, JSON, CURL_CONTENT_TYPE_SIZE};

struct curl_url_data {
	size_t size;
	char *data;
};

size_t curl_write_data(void *contents, size_t size, size_t nmemb, void *data);
bool Curl_Send(const std::string &, const std::string &, const std::string &, CURL_CONTENT_TYPE, const char *, OCTETSTRING &, OCTETSTRING &);
bool Curl_Send_ItsRequest(const std::string &, const std::string &, const std::string &, OCTETSTRING &, OCTETSTRING &);

#endif // UTILS_CURL_HH
