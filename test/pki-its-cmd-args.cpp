#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>
#include <boost/program_options.hpp>

#include "its/utils.hh"
#include "its/pki-its-cmd-args.hh"

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
		if (this->cmd_vm.count("profile"))
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
	url_ea =		getEnvVar(PKIITS_CMDARG_URL_EA);
	url_aa =		getEnvVar(PKIITS_CMDARG_URL_AA);
	url_its =		getEnvVar(PKIITS_CMDARG_URL_ITS);
	url_es =		getEnvVar(PKIITS_CMDARG_URL_ES);
	profile =		getEnvVar(PKIITS_CMDARG_PROFILE);
	eacert_b64 =		getEnvVar(PKIITS_CMDARG_EA_CERT);
	aacert_b64 =		getEnvVar(PKIITS_CMDARG_AA_CERT);
	its_tkey_b64 =		getEnvVar(PKIITS_CMDARG_ITS_TKEY);
	its_ec_cert_b64 =	getEnvVar(PKIITS_CMDARG_ITS_EC_CERT);
	its_ec_vkey_b64 =		getEnvVar(PKIITS_CMDARG_ITS_EC_VKEY);
	its_ec_ekey_b64 =		getEnvVar(PKIITS_CMDARG_ITS_EC_EKEY);
	its_ec_ekey_enable =   !getEnvVar(PKIITS_CMDARG_ITS_EC_EKEY_ENABLE).empty();
	its_at_cert_b64 =	getEnvVar(PKIITS_CMDARG_ITS_AT_CERT);
	its_at_vkey_b64 =		getEnvVar(PKIITS_CMDARG_ITS_AT_VKEY);
	its_at_ekey_b64 =		getEnvVar(PKIITS_CMDARG_ITS_AT_EKEY);
	its_at_ekey_enable =   !getEnvVar(PKIITS_CMDARG_ITS_AT_EKEY_ENABLE).empty();
	app_perms_ssp_bitmap =	getEnvVar(PKIITS_CMDARG_APP_PERMS_SSP_BITMAP);
	its_canonical_id = 	getEnvVar(PKIITS_CMDARG_ITS_CANONICAL_ID);

	if (!getEnvVar(PKIITS_CMDARG_APP_PERMS_PSID).empty())
		app_perms_psid = std::stol(getEnvVar(PKIITS_CMDARG_APP_PERMS_PSID));
	return true;
}


ItsPkiCmdArguments::ItsPkiCmdArguments(int argc, const char *argv[])
{
	init();

        try {
                this->desc.add_options()
                        (CMD_ARGUMENT_COMMAND, po::value<ItsPkiCmdArguments::CmdOperation>(), "PKI ITS tool command <string>")
                        ("in,i", po::value<std::string>()->notifier(notifier_on_input_file), "input file <string>")
			("ssl-client-cert", po::value<std::string>(&this->ssl_client_cert), "Client TLS/SSL certificate in one line <base64 string>")
			("ssl-client-key", po::value<std::string>(&this->ssl_client_key), "Client TLS/SSL key in one line <base64 string>")
			("ssl-ca-chain", po::value<std::string>(&this->ssl_ca_chain), "TLS/SSL CA chain in one line <base64 string>")
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
			("its-ec-vkey", po::value<std::string>(&this->its_ec_vkey), "ITS EC verification key <filename>")
			("its-ec-vkey-b64", po::value<std::string>(&this->its_ec_vkey_b64), "ITS EC verification key <filename>")
			("its-ec-ekey",   po::value<std::string>(&this->its_ec_ekey), "ITS EC decryption key <filename>")
			("its-ec-ekey-b64",   po::value<std::string>(&this->its_ec_ekey_b64), "ITS EC decryption key <filename>")
			("its-ec-ekey-enable", po::bool_switch(&this->its_ec_ekey_enable)->default_value(its_ec_ekey_enable), "Include encryption key into EC certificate request")
			("its-ec-cert", po::value<std::string>(&this->its_ec_certfile), "ITS EC certificate <filename>")
			("its-ec-cert-b64", po::value<std::string>(&this->its_ec_cert_b64), "ITS EC certificate <base64 string>")
			("its-ec-cert-save2file", po::value<std::string>(&this->its_ec_cert_save2file), "Save new ITS EC certificate to <filename>")
			("its-ec-vkey-save2file", po::value<std::string>(&this->its_ec_vkey_save2file), "Save new ITS EC verification key to <filename>")
			("its-ec-ekey-save2file", po::value<std::string>(&this->its_ec_ekey_save2file), "Save new ITS EC encryption key to <filename>")
			("its-at-vkey", po::value<std::string>(&this->its_at_vkey), "ITS AT verification key <filename>")
			("its-at-ekey",   po::value<std::string>(&this->its_at_ekey), "ITS AT decryption key <filename>")
			("its-at-ekey-enable", po::bool_switch(&this->its_at_ekey_enable)->default_value(its_at_ekey_enable), "Include encryption key into AT certificate request")
			("its-at-cert", po::value<std::string>(&this->its_at_certfile), "ITS AT certificate <filename>")
			("its-at-cert-b64", po::value<std::string>(&this->its_at_cert_b64), "ITS AT certificate <base64 string>")
			("its-at-cert-save2file", po::value<std::string>(&this->its_at_cert_save2file), "Save new ITS AT certificate to <filename>")
			("its-at-vkey-save2file", po::value<std::string>(&this->its_at_vkey_save2file), "Save new ITS AT verification key to <filename>")
			("its-at-ekey-save2file", po::value<std::string>(&this->its_at_ekey_save2file), "Save new ITS AT encryption key to <filename>")
			("aid-ssp", po::value<std::string>(&this->hexitsaidssplist), "AID SSP <hexadecimal string>")
			("app-perms-psid,p", po::value<long>(&this->app_perms_psid), "Application permissions: psid <int>")
			("app-perms-ssp-opaque", po::value<std::string>(&this->app_perms_ssp_opaque), "Application permissions: ssp, type 'opaque' <hexadecimal string>")
			("app-perms-ssp-bitmap", po::value<std::string>(&this->app_perms_ssp_bitmap), "Application permissions: ssp, type 'bitmap' <hexadecimal string>")
			("validity-restrictions,r", po::value<std::string>(&this->hexvalidityrestrictions), "Validity restrictions <hexadecimal string>")
			("its-name-header,n", po::value<std::string>(&this->its_name_header), "ITS name header <string>")
			("canonical-id,c", po::value<std::string>(&this->its_canonical_id), "ITS canonical ID <string>")
			("test-frequency,f", po::value<float>(&this->test_frequency), "Number of request per seconds  <float>")
			("number-of-cycles", po::value<long>(&this->cycles_num)->default_value(0), "Number of tests <long>")
			("number-of-threads", po::value<long>(&this->threads_num)->default_value(0), "Number of concurent threads <long>")
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
