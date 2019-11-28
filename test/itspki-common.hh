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

bool ParseItsRegisterCmdArguments(ItsPkiCmdArguments &cmd_args, ItsPkiInternalData &idata);
bool ParseEcEnrollmentCmdArguments(ItsPkiCmdArguments &cmd_args, ItsPkiInternalData &idata);
bool ParseAtEnrollmentCmdArguments(ItsPkiCmdArguments &cmd_args, ItsPkiInternalData &idata);

#endif // ITSPKI_COMMON_HH
