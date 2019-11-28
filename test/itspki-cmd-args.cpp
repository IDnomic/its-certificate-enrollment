#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>
#include <boost/program_options.hpp>

#include "its/utils.hh"
#include "itspki-cmd-args.hh"

using namespace boost::program_options;
namespace po  = boost::program_options;

void on_input_file(std::string in_file);

void
validate(boost::any& v, std::vector<std::string> const &values, ItsPkiCmdArguments::CmdOperation *, int)
{
        po::validators::check_first_occurrence(v);
        std::string const& cmd = validators::get_single_string(values);

	if (ItsPkiCmdArguments::IsValidOperation(cmd))
                v = boost::any(ItsPkiCmdArguments::CmdOperation(cmd));
        else
                throw po::validation_error(validation_error::invalid_option_value);
}


void
validate(boost::any& v, std::vector<std::string> const &values, ItsPkiCmdArguments::OutputFormat *, int)
{
        po::validators::check_first_occurrence(v);
        std::string const& ff = validators::get_single_string(values);

        if (ff == "json" || ff == "yaml")
                v = boost::any(ItsPkiCmdArguments::OutputFormat(ff));
        else
                throw po::validation_error(validation_error::invalid_option_value);
}


void
validate(boost::any& v, std::vector<std::string> const &values, ItsPkiCmdArguments::HashAlgorithmType *, int)
{
        po::validators::check_first_occurrence(v);
        std::string const& ff = validators::get_single_string(values);

        if (ff == "json" || ff == "yaml")
                v = boost::any(ItsPkiCmdArguments::HashAlgorithmType(ff));
        else
                throw po::validation_error(validation_error::invalid_option_value);
}


void
notifier_on_input_file(std::string in_file)
{
	std::cout << "Notifier: input file '" << in_file << "'" << std::endl;
}


bool
splitCanonicalId(std::string &cid, std::string &pid, std::string &sid)
{
	size_t pos = cid.rfind('.');
	if (pos == std::string::npos) 	{
		pid = cid;
		sid.erase();
	}
	else if (pos == (cid.length() - 1))   {
		pid = cid.substr(0, pos - 1);
		sid.erase();
	}
	else  {
		pid = cid.substr(0, pos);
		sid = cid.substr(pos+1);
	}

	cid.erase();

	return true;
}

bool
ItsPkiCmdArguments::ValidateOperation(void)
{
	if (!this->validated)
		return false;

	if (this->IsCmdHelp())   {
		return true;
	}
	else if (this->IsCmdInfo())   {
		if (this->cmd_vm.count("in") ||
				this->cmd_vm.count("ea-cert") || this->cmd_vm.count("ea-cert-b64") ||
				this->cmd_vm.count("aa-cert") || this->cmd_vm.count("aa-cert-b64"))
			return true;

		this->last_error_str = "missing ITS certificate as an input for the 'text' operation ('in', 'ea-cert', 'aa-cert', 'ea-cert-b64' or 'aa-cert-b64')";
	}
	else if (this->IsCmdItsRegister())   {
		if (this->cmd_vm.count("profile") || profile.length() > 0)
			return true;
		this->last_error_str = "'Profile' is mandatory option for this operation";
	}
	else if (this->IsCmdEcEnrollRequest())   {
		return true;
	}
	else if (this->IsCmdAtEnrollRequest())   {
		return true;
	}
	
	return false;
}


bool
ItsPkiCmdArguments::init()
{
	keep_its =		!getEnvVar(PKIITS_CMDARG_KEEP_ITS).empty();
	user_password =		getEnvVar(PKIITS_CMDARG_USER_PASSWORD);
	url_ea =		getEnvVar(PKIITS_CMDARG_URL_EA);
	url_aa =		getEnvVar(PKIITS_CMDARG_URL_AA);
	url_its =		getEnvVar(PKIITS_CMDARG_URL_ITS);
	url_es =		getEnvVar(PKIITS_CMDARG_URL_ES);
	profile =		getEnvVar(PKIITS_CMDARG_PROFILE);
	eacert_b64 =		getEnvVar(PKIITS_CMDARG_EA_CERT);
	aacert_b64 =		getEnvVar(PKIITS_CMDARG_AA_CERT);
	its_tkey_b64 =		getEnvVar(PKIITS_CMDARG_ITS_TKEY);
	its_ec_cert_b64 =	getEnvVar(PKIITS_CMDARG_ITS_EC_CERT);
	its_ec_vkey_b64 =	getEnvVar(PKIITS_CMDARG_ITS_EC_VKEY);
	its_ec_ekey_b64 =	getEnvVar(PKIITS_CMDARG_ITS_EC_EKEY);
	its_ec_ekey_enable =   !getEnvVar(PKIITS_CMDARG_ITS_EC_EKEY_ENABLE).empty();
	its_at_cert_b64 =	getEnvVar(PKIITS_CMDARG_ITS_AT_CERT);
	its_at_vkey_b64 =		getEnvVar(PKIITS_CMDARG_ITS_AT_VKEY);
	its_at_ekey_b64 =		getEnvVar(PKIITS_CMDARG_ITS_AT_EKEY);
	its_at_ekey_enable =   !getEnvVar(PKIITS_CMDARG_ITS_AT_EKEY_ENABLE).empty();
	its_need_to_register = !getEnvVar(PKIITS_CMDARG_ITS_NEED_TO_REGISTER).empty();
	its_need_ec_enrollment =	!getEnvVar(PKIITS_CMDARG_ITS_NEED_EC_ENROLLMENT).empty();

	its_canonical_id = 	getEnvVar(PKIITS_CMDARG_ITS_CANONICAL_ID);
	its_serial_id_hex = 	getEnvVar(PKIITS_CMDARG_ITS_SERIAL_ID);
	its_prefix_id = 	getEnvVar(PKIITS_CMDARG_ITS_PREFIX_ID);

	ec_psidssp_seq =	getEnvVar(PKIITS_CMDARG_EC_PSIDSSP_SEQ);
	at_psidssp_seq =	getEnvVar(PKIITS_CMDARG_AT_PSIDSSP_SEQ);

	std::cout << "Profile: " << profile << std::endl;
	std::cout << "its_at_ekey_enable: " << its_at_ekey_enable << std::endl;

	if (its_prefix_id.empty() && its_serial_id_hex.empty())   {
		if (!its_canonical_id.empty())   {
			splitCanonicalId(its_canonical_id, its_prefix_id, its_serial_id_hex);
		}
		else   {
			its_prefix_id.assign("BENCH-ITSPKI-");
			its_serial_id_hex.assign("generate");
		}
	}
	else   {
		its_canonical_id.erase();
	}

	if (!getEnvVar(PKIITS_CMDARG_CYCLES_PER_THREAD).empty())
		cycles_num = std::stol(getEnvVar(PKIITS_CMDARG_CYCLES_PER_THREAD));
	if (cycles_num == 0)
		cycles_num = INT_MAX;

	if (!getEnvVar(PKIITS_CMDARG_THREADS).empty())
		threads_num = std::stol(getEnvVar(PKIITS_CMDARG_THREADS));

	if (!getEnvVar(PKIITS_CMDARG_TEST_FREQUENCY).empty())
		test_frequency = std::stof(getEnvVar(PKIITS_CMDARG_TEST_FREQUENCY));
	else
		test_frequency = 0.0;

	return true;
}


ItsPkiCmdArguments::ItsPkiCmdArguments(int argc, const char *argv[])
{
	init();

        try {
                this->desc.add_options()
                        (CMD_ARGUMENT_COMMAND, po::value<ItsPkiCmdArguments::CmdOperation>(), "PKI ITS tool command <string>")
			("keep-its", po::bool_switch(&this->keep_its)->default_value(keep_its), "Do not delete test ITSs")
                        ("in,i", po::value<std::string>()->notifier(notifier_on_input_file), "input file <string>")
			("ssl-client-cert", po::value<std::string>(&this->ssl_client_cert), "Client TLS/SSL certificate in one line <base64 string>")
			("ssl-client-key", po::value<std::string>(&this->ssl_client_key), "Client TLS/SSL key in one line <base64 string>")
			("ssl-ca-chain", po::value<std::string>(&this->ssl_ca_chain), "TLS/SSL CA chain in one line <base64 string>")
			("user-password", po::value<std::string>(&this->user_password), "User:Password to access ITS operator service")
			("url-ea,H", po::value<std::string>(&this->url_ea), "URL of EA <URL string>")
			("url-aa,U", po::value<std::string>(&this->url_aa), "URL of AA <URL string>")
			("url-its,I", po::value<std::string>(&this->url_its), "URL of Registration Entity <URL string>")
			("url-es,Z", po::value<std::string>(&this->url_es), "URL of Elastic-search log server <URL string>")
			("profile,P", po::value<std::string>(&this->profile), "ITS profile ID <string>")
			("ea-cert,E", po::value<std::string>(&this->eacertfile), "EA certificate <filename>")
			("ea-cert-b64,e", po::value<std::string>(&this->eacert_b64), "EA certificate <base64 string>")
			("aa-cert,A", po::value<std::string>(&this->aacertfile), "AA certificate <filename>")
			("aa-cert-b64,a", po::value<std::string>(&this->aacert_b64), "AA certificate <base64 string>")
			("its-tkey", po::value<std::string>(&this->its_tkey), "Technical Key <filename>")
			("its-tkey-b64", po::value<std::string>(&this->its_tkey_b64), "Technical Key <base64 string>")
			("its-need-to-register", po::bool_switch(&this->its_need_to_register)->default_value(its_need_to_register), "Register ITS before EC certificate request")
			("its-ec-vkey", po::value<std::string>(&this->its_ec_vkey), "ITS EC verification key <filename>")
			("its-ec-vkey-b64", po::value<std::string>(&this->its_ec_vkey_b64), "ITS EC verification key <filename>")
			("its-ec-ekey",   po::value<std::string>(&this->its_ec_ekey), "ITS EC decryption key <filename>")
			("its-ec-ekey-b64",   po::value<std::string>(&this->its_ec_ekey_b64), "ITS EC decryption key <filename>")
			("its-ec-ekey-enable", po::bool_switch(&this->its_ec_ekey_enable)->default_value(its_ec_ekey_enable), "Include encryption key into EC certificate request")
			("its-ec-cert", po::value<std::string>(&this->its_ec_certfile), "ITS EC certificate <filename>")
			("its-ec-cert-b64", po::value<std::string>(&this->its_ec_cert_b64), "ITS EC certificate <base64 string>")
			("its-ec-save", po::bool_switch(&this->its_ec_save)->default_value(its_ec_save), "Save EC enrollment results (keys and certificate)")
			("its-need-ec-enrollment", po::bool_switch(&this->its_need_ec_enrollment)->default_value(its_need_ec_enrollment), "EC enrollment needed (for AT operations)")
			("its-at-vkey", po::value<std::string>(&this->its_at_vkey), "ITS AT verification key <filename>")
			("its-at-ekey",   po::value<std::string>(&this->its_at_ekey), "ITS AT decryption key <filename>")
			("its-at-ekey-enable", po::bool_switch(&this->its_at_ekey_enable)->default_value(its_at_ekey_enable), "Include encryption key into AT certificate request")
			("its-at-cert", po::value<std::string>(&this->its_at_certfile), "ITS AT certificate <filename>")
			("its-at-cert-b64", po::value<std::string>(&this->its_at_cert_b64), "ITS AT certificate <base64 string>")
			("its-at-save", po::bool_switch(&this->its_at_save)->default_value(its_at_save), "Save AT enrollment results (keys and certificate)")
			("aid-ssp", po::value<std::string>(&this->hexitsaidssplist), "AID SSP <hexadecimal string>")
			("ec-psidssp-seq", po::value<std::string>(&this->ec_psidssp_seq), "EC application permission sequence: <int:hex*?, >")
			("at-psidssp-seq", po::value<std::string>(&this->at_psidssp_seq), "AT application permission sequence: <int:hex*?, >")
			("validity-restrictions,r", po::value<std::string>(&this->hexvalidityrestrictions), "Validity restrictions <hexadecimal string>")
			("canonical-id", po::value<std::string>(&this->its_canonical_id), "ITS canonical ID string <prefix(ascii).serial(hex)>")
			// ("canonical-id-b64", po::value<std::string>(&this->its_canonical_id_b64), "ITS canonical ID <base 64 string>")
			("its-prefix_id,n", po::value<std::string>(&this->its_prefix_id), "ITS prefix ID <string>")
			("its-serial-id", po::value<std::string>(&this->its_serial_id_hex), "ITS serial ID <hex string>")
			("test-frequency,f", po::value<float>(&this->test_frequency), "Number of request per seconds  <float>")
			("number-of-cycles", po::value<long>(&this->cycles_num), "Number of tests <long>")
			("number-of-threads", po::value<long>(&this->threads_num), "Number of concurent threads <long>")
			(CMD_ARGUMENT_FORMAT, po::value<ItsPkiCmdArguments::OutputFormat>(), "Info output format <string>")
			(CMD_ARGUMENT_HASH_ALGORITHM, po::value<ItsPkiCmdArguments::HashAlgorithmType>(), "Hash algorithm <string>")
                        ("help,h", "Help screen")
			("bench", po::bool_switch(&this->do_bench)->default_value(false), "Execute bench test")
                        ;

                po::positional_options_description pos_desc;
                pos_desc.add("command", 1);

                po::command_line_parser parser{argc, argv};
                parser.options(desc).positional(pos_desc).allow_unregistered();
                po::parsed_options parsed_options = parser.run();

                po::store(parsed_options, this->cmd_vm);
                notify(this->cmd_vm);
		this->validated = true;
        }
        catch (const error &ex)   {
                std::cerr << "Command line arguments error: " << ex.what() << std::endl;
		this->last_error_str = ex.what();
		this->validated = false;
        }
}
