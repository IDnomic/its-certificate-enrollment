#ifndef ITS_PKI_CMD_ARGS_HH
#define ITS_PKI_CMD_ARGS_HH

#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <boost/program_options.hpp>

#include "its/its-asn1-modules.hh"

#define CMD_ARGUMENT_COMMAND "command"
#define CMD_ARGUMENT_FORMAT "output-format"
#define CMD_ARGUMENT_HASH_ALGORITHM "hash-algorithm"

#define CMD_NAME_HELP "help"
#define CMD_NAME_INFO "info"
#define CMD_NAME_ITS_REGISTER "its-register"
#define CMD_NAME_EC_CREATE_ENROLL_REQUEST "ec-create-enroll-request"
#define CMD_NAME_AT_CREATE_ENROLL_REQUEST "at-create-enroll-request"

using namespace boost::program_options;
namespace po  = boost::program_options;

enum type_cmd_operation_t {
	CMD_TYPE_NULL = 0,
	CMD_TYPE_HELP,
	CMD_TYPE_INFO,
	CMD_TYPE_ITS_REGISTER,
	CMD_TYPE_EC_CREATE_ENROLL_REQUEST,
	CMD_TYPE_AT_CREATE_ENROLL_REQUEST,
};

enum type_format_t {
	TYPE_FORMAT_JSON = 0,
	TYPE_FORMAT_YAML,
};

static std::map<std::string, type_cmd_operation_t > valid_operations = {
	{ CMD_NAME_HELP, 			CMD_TYPE_HELP},
	{ CMD_NAME_INFO,			CMD_TYPE_INFO},
	{ CMD_NAME_ITS_REGISTER,		CMD_TYPE_ITS_REGISTER},
	{ CMD_NAME_EC_CREATE_ENROLL_REQUEST,	CMD_TYPE_EC_CREATE_ENROLL_REQUEST},
	{ CMD_NAME_AT_CREATE_ENROLL_REQUEST,	CMD_TYPE_AT_CREATE_ENROLL_REQUEST},
};

class ItsPkiCmdArguments {
private:
	po::options_description desc{"CmdArguments"};
	variables_map cmd_vm;
	bool validated = false;
	std::string last_error_str;
	bool init();

public:
	ItsPkiCmdArguments() {};
	ItsPkiCmdArguments(int argc, const char *argv[]);

	type_cmd_operation_t GetOperation() {
		if (this->cmd_vm.count(CMD_ARGUMENT_COMMAND))
			return this->cmd_vm[CMD_ARGUMENT_COMMAND].as<CmdOperation>().getValue();
		else
			return CMD_TYPE_NULL; 
	};

	type_format_t GetFormat() {
		if (this->cmd_vm.count(CMD_ARGUMENT_FORMAT))
			return this->cmd_vm[CMD_ARGUMENT_FORMAT].as<OutputFormat>().getValue();
		else
			return TYPE_FORMAT_JSON; 
	};

	IEEE1609dot2BaseTypes::HashAlgorithm::enum_type GetHashAlgorithm() {
		if (this->cmd_vm.count(CMD_ARGUMENT_HASH_ALGORITHM))
			return this->cmd_vm[CMD_ARGUMENT_HASH_ALGORITHM].as<HashAlgorithmType>().getValue();
		else
			return IEEE1609dot2BaseTypes::HashAlgorithm::sha256;
	};

	std::string GetInputFile()   {
		return this->cmd_vm["in"].as<std::string>();
	};

	bool IsCmdHelp() { return (GetOperation() == CMD_TYPE_HELP); };
	bool IsCmdInfo() { return (GetOperation() == CMD_TYPE_INFO); };
	bool IsCmdItsRegister() { return (GetOperation() == CMD_TYPE_ITS_REGISTER); };
	bool IsCmdEcEnrollRequest() { return (GetOperation() == CMD_TYPE_EC_CREATE_ENROLL_REQUEST); };
	bool IsCmdAtEnrollRequest() { return (GetOperation() == CMD_TYPE_AT_CREATE_ENROLL_REQUEST); };
	bool IsFormatJson() { return (GetFormat() == TYPE_FORMAT_JSON); };
	bool IsFormatYaml() { return (GetFormat() == TYPE_FORMAT_YAML); };
	static bool IsValidOperation(std::string cmd) { return (valid_operations.find(cmd) != valid_operations.end()); };
	bool IsBench() { return do_bench; };

	void PrintHelp(std::ostream& os, unsigned width = 0) { this->desc.print(os, width); }; 
	std::string GetLastErrorString() { return this->last_error_str; };

	bool ValidateOperation(void);

	std::string url_ea;
	std::string url_aa;
	std::string url_its;
	std::string url_es;
	std::string profile;
	std::string its_name_header;
	std::string its_canonical_id;
	int test_period_ms;
	float test_frequency;

	std::string ssl_client_cert;
	std::string ssl_client_key;
	std::string ssl_ca_chain;

	std::string app_perms_ssp_opaque;
	std::string app_perms_ssp_bitmap;
	long app_perms_psid = 0;
	std::string hexitsaidssplist;
	std::string hexvalidityrestrictions;
	std::string eacertfile;
	std::string eacert_b64;
	std::string aacertfile;
	std::string aacert_b64;
	std::string its_tkey;
	std::string its_tkey_b64;
	
	std::string its_ec_certfile;
	std::string its_ec_cert_b64;
	std::string its_ec_vkey;
	std::string its_ec_vkey_b64;
	std::string its_ec_ekey;
	std::string its_ec_ekey_b64;
	bool its_ec_ekey_enable = false;
	std::string its_ec_cert_save2file;
	std::string its_ec_vkey_save2file;
	std::string its_ec_ekey_save2file;
	
	std::string its_at_certfile;
	std::string its_at_cert_b64;
	std::string its_at_vkey;
	std::string its_at_vkey_b64;
	std::string its_at_ekey;
	std::string its_at_ekey_b64;
	bool its_at_ekey_enable = false;
	std::string its_at_cert_save2file;
	std::string its_at_vkey_save2file;
	std::string its_at_ekey_save2file;
	
	int wantedstart;
	int taiutc;
	long cycles_num;
	long threads_num;
	bool do_bench;

	int debug;
	int enable_log;

	class CmdOperation {
	public:
	        CmdOperation(std::string const& val) {
			if (val.empty())
				_cmd = CMD_TYPE_NULL;
			else if (valid_operations.find(val) == valid_operations.end())
				throw po::validation_error(validation_error::invalid_option_value, CMD_ARGUMENT_COMMAND);

			_cmd = valid_operations[val];
		};

		type_cmd_operation_t getValue(void) const { return _cmd; };
	private:
		type_cmd_operation_t _cmd;
	};

	class OutputFormat {
	public:
	        OutputFormat(std::string const& var)  {
			if (var.empty())
				_format = TYPE_FORMAT_JSON;
			else if (!var.compare("json"))
				_format = TYPE_FORMAT_JSON;
			else if (!var.compare("yaml"))
				_format = TYPE_FORMAT_YAML;
			else
				throw po::validation_error(validation_error::invalid_option_value);
		};
		type_format_t  getValue(void) const { return _format; };
	private:
		type_format_t _format;
	};

	class HashAlgorithmType {
	public:
	        HashAlgorithmType(std::string const& var)  {
			if (var.empty())
				_hash_algorithm = IEEE1609dot2BaseTypes::HashAlgorithm::sha256;
			else if (!var.compare("sha256"))
				_hash_algorithm = IEEE1609dot2BaseTypes::HashAlgorithm::sha256;
			else if (!var.compare("sha384"))
				_hash_algorithm = IEEE1609dot2BaseTypes::HashAlgorithm::sha384;
			else
				throw po::validation_error(validation_error::invalid_option_value);
		};
		IEEE1609dot2BaseTypes::HashAlgorithm::enum_type   getValue(void) const { return _hash_algorithm; };
	private:
		IEEE1609dot2BaseTypes::HashAlgorithm::enum_type  _hash_algorithm;
	};
};


#define PKIITS_CMDARG_URL_EA	"PKIITS_CMDARG_URL_EA"
#define PKIITS_CMDARG_URL_AA	"PKIITS_CMDARG_URL_AA"
#define PKIITS_CMDARG_URL_ITS	"PKIITS_CMDARG_URL_ITS"
#define PKIITS_CMDARG_URL_ES	"PKIITS_CMDARG_URL_ES"

#define PKIITS_CMDARG_PROFILE	"PKIITS_CMDARG_PROFILE"
#define PKIITS_CMDARG_EA_CERT	"PKIITS_CMDARG_EA_CERT"
#define PKIITS_CMDARG_AA_CERT	"PKIITS_CMDARG_AA_CERT"
#define PKIITS_CMDARG_ITS_TKEY	"PKIITS_CMDARG_ITS_TKEY"
#define PKIITS_CMDARG_ITS_EC_CERT		"PKIITS_CMDARG_ITS_EC_CERT"
#define PKIITS_CMDARG_ITS_EC_VKEY		"PKIITS_CMDARG_ITS_EC_VKEY"
#define PKIITS_CMDARG_ITS_EC_EKEY		"PKIITS_CMDARG_ITS_EC_EKEY"
#define PKIITS_CMDARG_ITS_EC_EKEY_ENABLE	"PKIITS_CMDARG_ITS_EC_EKEY_ENABLE"
#define PKIITS_CMDARG_ITS_AT_CERT		"PKIITS_CMDARG_ITS_AT_CERT"
#define PKIITS_CMDARG_ITS_AT_VKEY		"PKIITS_CMDARG_ITS_AT_VKEY"
#define PKIITS_CMDARG_ITS_AT_EKEY		"PKIITS_CMDARG_ITS_AT_EKEY"
#define PKIITS_CMDARG_ITS_AT_EKEY_ENABLE	"PKIITS_CMDARG_ITS_AT_EKEY_ENABLE"
#define PKIITS_CMDARG_AID_SSP		"PKIITS_CMDARG_AID_SSP"
#define PKIITS_CMDARG_APP_PERMS_PSID	"PKIITS_CMDARG_APP_PERMS_PSID"
#define PKIITS_CMDARG_APP_PERMS_SSP_OPAQUE	"PKIITS_CMDARG_APP_PERMS_SSP_OPAQUE"
#define PKIITS_CMDARG_APP_PERMS_SSP_BITMAP	"PKIITS_CMDARG_APP_PERMS_SSP_BITMAP"
#define PKIITS_CMDARG_ITS_CANONICAL_ID	"PKIITS_CMDARG_ITS_CANONICAL_ID" 

#define PKIITS_CMDARG_	"PKIITS_CMDARG_"

#endif // ifndef ITS_PKI_CMD_ARGS_HH
