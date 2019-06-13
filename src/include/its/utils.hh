#ifndef UTILS_CPP_HH
#define UTILS_CPP_HH

#include <string>
#include <iostream>
#include <memory>

#include "its/utils-ttcn.hh"
#include "its/utils-openssl.hh"

// template<typename ... Args>
// std::string string_format(const std::string& format, Args ... args);
std::string string_format(const std::string fmt, ...);
std::string getEnvVar( std::string const & );
bool read_bytes(const std::string &, OCTETSTRING &);
int writeToFile(const char *, const unsigned char *, size_t);

#endif // UTILS_CPP_HH
