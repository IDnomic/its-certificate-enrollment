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
#include "itspki-common.hh"
// #include "utils-curl.hh"

// using namespace boost::program_options;
// namespace po  = boost::program_options;

#if 0
#define BENCH_DATA_MAGIC 0xEC6E4513
struct bench_data {
	const char *url;
	const char *url_report;
	long cycles_num;

	unsigned magic;
};

pthread_mutex_t mutex_print = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_counter = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_ttcn = PTHREAD_MUTEX_INITIALIZER;

static int thread_counter = 0;

bool
ItsRegisterRequest_Process(const char *user_password, const char *url, const char *url_report,
                ItsPkiInternalData &idata, ItsPkiSession &session)
{
        DEBUG_STREAM_CALLED;

        OCTETSTRING request;
        if (!session.ItsRegisterRequest_Create(idata, request))  {
                ERROR_STREAM << "Cannot compose ItsRegister request" << std::endl;
                return false;
        }
        dump_ttcn_object(request, "its register request: ");

        OCTETSTRING response_raw;
	std::string identity = session.sessionGetCanonicalId(idata);
        if (!Curl_Send(url, NULL, JSON, user_password, request, response_raw, NULL))   {
                ERROR_STREAM << "request send error" << std::endl;
                return false;
        }
        dump_ttcn_object(response_raw, "its register response: ");

        OCTETSTRING cert_encoded;
        if (!session.ItsRegisterResponse_Parse(response_raw, cert_encoded))   {
                ERROR_STREAM << "cannot parse ItsRegister response" << std::endl;
                return false;
        }
        
	DEBUG_STREAM_RETURNS_OK;
        return true;
}


bool
EcEnrollmentRequest_Process(const std::string &url_ea, const std::string &url_es,
		ItsPkiInternalData &idata, ItsPkiSession &session)
{
        DEBUG_STREAM_CALLED;

        OCTETSTRING data_encrypted;
        if (!session.EcEnrollmentRequest_Create(idata, data_encrypted))   {
                ERROR_STREAM << "Create EC enrollment request failed" << std::endl;
                return false;
        }

        OCTETSTRING response_raw;
	const std::string identity = session.sessionGetCanonicalId(idata);
	if (!Curl_Send_ItsRequest(url_ea.c_str(), data_encrypted, response_raw, NULL))   {
                ERROR_STREAM << "request send error" << std::endl;
                return false;
	}

        OCTETSTRING cert_encoded;
        if (!session.EcEnrollmentResponse_Parse(response_raw, cert_encoded))   {
                ERROR_STREAM << "parse response error" << std::endl;
                return false;
        }

        DEBUG_STREAM_RETURNS_OK;
        return true;
}


bool
AtEnrollmentRequest_Process(const std::string &url_at, const std::string &url_es,
		ItsPkiInternalData &idata, ItsPkiSession &session)
{
        DEBUG_STREAM_CALLED;

        OCTETSTRING atRequest_encoded;
        if (!session.AtEnrollmentRequest_InnerAtRequest(idata, atRequest_encoded))  {
                ERROR_STREAM << "Cannot compose AT request" << std::endl;
                return false;
        }

        OCTETSTRING response_raw;
	const std::string identity = session.sessionGetCanonicalId(idata);
	if (!Curl_Send_ItsRequest(url_at.c_str(), atRequest_encoded, response_raw, NULL))   {
                ERROR_STREAM << "request send error" << std::endl;
                return false;
	}
        
	OCTETSTRING cert_encoded;
        if (!session.AtEnrollmentResponse_Parse(response_raw, cert_encoded))   {
                ERROR_STREAM << "cannot parse At Enrollment response" << std::endl;
                return false;
        }

        DEBUG_STREAM_RETURNS_OK;
        return true;
}

#endif

bool
ParseItsRegisterCmdArguments(ItsPkiCmdArguments &cmd_args, ItsPkiInternalData &idata)
{
        DEBUG_STREAM_CALLED;

        if (cmd_args.profile.empty())   {
                ERROR_STREAM << "ItsRegister: missing mandatory 'profile' argument" << std::endl;
                return false;
        }
        idata.SetProfile(cmd_args.profile);

        // ITS Technical Key
        void *key = NULL;
        if (!cmd_args.its_tkey.empty())
                key = ECKey_ReadPrivateKey(cmd_args.its_tkey.c_str());
        else if (!cmd_args.its_tkey_b64.empty())
                key = ECKey_ReadPrivateKeyB64(cmd_args.its_tkey_b64.c_str());
	if (key != NULL)   {
        	if (!idata.SetItsTechnicalKey(key))   {
                	ERROR_STREAM << "EC enroll: Missing or invalid technical key" << std::endl;
                	return false;
        	}
	}
	else if (!cmd_args.its_need_to_register)   {
                ERROR_STREAM << "EC enroll arguments: no ITS Technical Key, no request to register a new ITS" << std::endl;
                return false;
	}

	idata.SetItsRegistrationFlag(cmd_args.its_need_to_register);

	if (!idata.SetCanonicalID(cmd_args.its_canonical_id, cmd_args.its_name_header, idata.GetItsTechnicalKey()))   {
                ERROR_STREAM << "EC enroll arguments: cannot set ITS canonical ID" << std::endl;
                return false;
        }

        DEBUG_STREAM_RETURNS_OK;
        return true;
}


bool
ParseEcEnrollmentCmdArguments(ItsPkiCmdArguments &cmd_args, ItsPkiInternalData &idata)
{
	DEBUG_STREAM_CALLED;

	void *key = NULL;
	// ITS Technical Key
	if (!cmd_args.its_tkey.empty())
		key = ECKey_ReadPrivateKey(cmd_args.its_tkey.c_str());	
	else if (!cmd_args.its_tkey_b64.empty())
		key = ECKey_ReadPrivateKeyB64(cmd_args.its_tkey_b64.c_str());
	if (key != NULL)   {
		if (!idata.SetItsTechnicalKey(key))   {
			ERROR_STREAM << "EC enroll: Missing or invalid technical key" << std::endl;
			return false;
		}
	}
	else {
		if (!ParseItsRegisterCmdArguments(cmd_args, idata))   {
			ERROR_STREAM << "Ec enroll: need valid ITS registration arguments" << std::endl;
			return false;
		}
	}
	
	// ITS Ec Verification Key
	key = NULL;
	if (!cmd_args.its_ec_vkey.empty())
		key = ECKey_ReadPrivateKey(cmd_args.its_ec_vkey.c_str()); 
	else if (!cmd_args.its_ec_vkey_b64.empty())
		key = ECKey_ReadPrivateKeyB64(cmd_args.its_ec_vkey_b64.c_str()); 
	if (key != NULL)
		idata.SetItsEcVerificationKey(key);

	// ITS Ec Encryption Key
	if (cmd_args.its_ec_ekey_enable)   {
		idata.SetItsEcEncryptionKeyEnable(true);
		
		key = NULL;
		if (!cmd_args.its_ec_ekey.empty())
			key = ECKey_ReadPrivateKey(cmd_args.its_ec_ekey.c_str()); 
		else if (!cmd_args.its_ec_ekey_b64.empty())
			key = ECKey_ReadPrivateKeyB64(cmd_args.its_ec_ekey_b64.c_str()); 
		if (key != NULL)
			idata.SetItsEcEncryptionKey(key);
	}

	// Parse EA certificate
	OCTETSTRING blob;
	if (!cmd_args.eacertfile.empty())   {
		read_bytes(cmd_args.eacertfile, blob);
	}
	else if (!cmd_args.eacert_b64.empty())   {
		blob = decode_base64(cmd_args.eacert_b64.c_str());
	}
	else   {
		ERROR_STREAM << "EC enroll: EA certificate is mandatory "<< std::endl;
		return false;
	}
	if (!idata.SetEAEncryptionKey(blob))   {
		ERROR_STREAM << "EC enroll arguments: cannot set EA encryption key from cert file or b64-string " << cmd_args.eacertfile << "'" << std::endl;
		return false;
	}

	// Set permissions
	if (!idata.EcAddAidSsp(cmd_args.ec_psidssp_seq))   {
		ERROR_STREAM << "EC enroll arguments: cannot set ITS AID SSP list" << std::endl;
		return false;
	}
        dump_ttcn_object(idata.EcGetAppPermsSsp(), "ITS EC AID-SSP: ");

	// Set ITS Hash algorithm
	if (!idata.SetHashAlgorithm(cmd_args.GetHashAlgorithm()))   {
		ERROR_STREAM << "EC enroll arguments: cannot set Hash algorithm" << std::endl;
		return false;
	}

	// Create/Set ITS canonical ID
	if (!idata.SetCanonicalID(cmd_args.its_canonical_id, cmd_args.its_name_header, idata.GetItsTechnicalKey()))   {
		ERROR_STREAM << "EC enroll arguments: cannot set ITS canonical ID" << std::endl;
		return false;
	}
	DEBUG_STREAM << "ITS Canonical ID: '" << idata.GetCanonicalId() << "'" << std::endl;

	DEBUG_STREAM_RETURNS_OK;
	return true;
}


bool
ParseAtEnrollmentCmdArguments(ItsPkiCmdArguments &cmd_args, ItsPkiInternalData &idata)
{
	DEBUG_STREAM_CALLED;

	void *key = NULL;
	if (!cmd_args.its_at_vkey.empty())
		key = ECKey_ReadPrivateKey(cmd_args.its_at_vkey.c_str()); 
	else if (!cmd_args.its_at_vkey_b64.empty())
		key = ECKey_ReadPrivateKeyB64(cmd_args.its_at_vkey_b64.c_str()); 
	idata.SetItsAtVerificationKey(key);

	if (cmd_args.its_at_ekey_enable)   {
		idata.SetItsAtEncryptionKeyEnable(true);
		
		key = NULL;
		if (!cmd_args.its_at_ekey.empty())
			key = ECKey_ReadPrivateKey(cmd_args.its_at_ekey.c_str()); 
		else if (!cmd_args.its_at_ekey_b64.empty())
			key = ECKey_ReadPrivateKeyB64(cmd_args.its_at_ekey_b64.c_str()); 
		idata.SetItsAtEncryptionKey(key);
	}

	// Parse EA certificate
	OCTETSTRING blob;
	if (!cmd_args.eacertfile.empty())   {
		read_bytes(cmd_args.eacertfile, blob);
	}
	else if (!cmd_args.eacert_b64.empty())   {
		blob = decode_base64(cmd_args.eacert_b64.c_str());
	}
	else   {
		ERROR_STREAM << "AT enroll: EA certificate is mandatory "<< std::endl;
		return false;
	}
	if (!idata.SetEAEncryptionKey(blob))   {
		ERROR_STREAM << "AT enroll arguments: cannot set EA encryption key from cert file or b64-string " << cmd_args.eacertfile << "'" << std::endl;
		return false;
	}

	blob.clean_up();
	if (!cmd_args.aacertfile.empty())   {
		read_bytes(cmd_args.aacertfile, blob);
	}
	else if (!cmd_args.aacert_b64.empty())   {
		blob = decode_base64(cmd_args.aacert_b64.c_str());
	}
	else   {
		ERROR_STREAM << "AT enroll: AA certificate is mandatory "<< std::endl;
		return false;
	}
	if (!idata.SetAAEncryptionKey(blob))   {
		ERROR_STREAM << "AT enroll arguments: cannot set AA encryption key from cert file or b64-string " << cmd_args.aacertfile << "'" << std::endl;
		return false;
	}


	if (cmd_args.its_need_ec_enrollment)   {
		if (!ParseEcEnrollmentCmdArguments(cmd_args, idata))   {
			ERROR_STREAM << "AT enroll: EA certificate is mandatory "<< std::endl;
			return false;
		}

		idata.SetEcEnrollmentFlag(true);
	}
	else   {
		blob.clean_up();
		if (!cmd_args.its_ec_certfile.empty())   {
			read_bytes(cmd_args.its_ec_certfile, blob);
		}
		else if (!cmd_args.its_ec_cert_b64.empty())   {
			blob = decode_base64(cmd_args.its_ec_cert_b64.c_str());
		}
		else   {
			ERROR_STREAM << "AT enroll: ITS EC certificate is mandatory "<< std::endl;
			return false;
		}
		if (!idata.SetItsEcId(blob))   {
			ERROR_STREAM << "AT enroll arguments: cannot set ITS EC ID" << std::endl;
			return false;
		}

		key = NULL;
		if (!cmd_args.its_ec_vkey.empty())
			key = ECKey_ReadPrivateKey(cmd_args.its_ec_vkey.c_str()); 
		else if (!cmd_args.its_ec_vkey_b64.empty())
			key = ECKey_ReadPrivateKeyB64(cmd_args.its_ec_vkey_b64.c_str()); 
		idata.SetItsEcVerificationKey(key);

		// Create/Set ITS canonical ID
		if (!idata.SetCanonicalID(cmd_args.its_canonical_id, cmd_args.its_name_header, idata.GetItsTechnicalKey()))   {
			ERROR_STREAM << "AT enroll arguments: cannot set ITS canonical ID" << std::endl;
			return false;
		}
		DEBUG_STREAM << "ITS Canonical ID: '" << idata.GetCanonicalId() << "'" << std::endl;
	}
	
	// Set permissions
	if (!idata.AtAddAidSsp(cmd_args.at_psidssp_seq))   {
		ERROR_STREAM << "AT enroll arguments: cannot set ITS AT AID-SSP list" << std::endl;
		return false;
	}
        dump_ttcn_object(idata.AtGetAppPermsSsp(), "ITS AT AID-SSP: ");

	// Set ITS Hash algorithm
	if (!idata.SetHashAlgorithm(cmd_args.GetHashAlgorithm()))   {
		ERROR_STREAM << "EC enroll arguments: cannot set Hash algorithm" << std::endl;
		return false;
	}

	DEBUG_STREAM_RETURNS_OK;
        return true;
}

