#ifndef ITSPKI_COMMON_HH
#define ITSPKI_COMMON_HH

#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <boost/program_options.hpp>

#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>
#include <boost/program_options.hpp>

#include "TTCN3.hh"
#include "EtsiTs103097Module.hh"

#include "its/itspki-debug.hh"
#include "its/itspki-internal-data.hh"
#include "its/itspki-session.hh"
#include "its/utils.hh"

#include "itspki-cmd-args.hh"
// #include "utils-curl.hh"

bool ParseItsRegisterCmdArguments(ItsPkiCmdArguments &cmd_args, ItsPkiInternalData &idata);
bool ParseEcEnrollmentCmdArguments(ItsPkiCmdArguments &cmd_args, ItsPkiInternalData &idata);
bool ParseAtEnrollmentCmdArguments(ItsPkiCmdArguments &cmd_args, ItsPkiInternalData &idata);

/*
bool ItsRegisterRequest_Process(const char *, const char *, const char *, ItsPkiInternalData &, ItsPkiSession &);
bool EcEnrollmentRequest_Process(const std::string &url_ea, const std::string &url_es, ItsPkiInternalData &idata, ItsPkiSession &session);
bool AtEnrollmentRequest_Process(const std::string &url_at, const std::string &url_es, ItsPkiInternalData &idata, ItsPkiSession &session);
*/

// bool EcEnrollmentRequest_Bench(const std::string &url, const std::string &url_report, long cycles_num, long threads_num, ItsPkiInternalData &idata);
// bool AtEnrollmentRequest_Bench(const std::string &url, const std::string &url_report, long cycles_num, long threads_num, ItsPkiInternalData &idata);

#endif // ITSPKI_COMMON_HH
