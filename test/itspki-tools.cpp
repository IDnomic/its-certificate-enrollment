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
#include "utils-curl.hh"

using namespace boost::program_options;
namespace po  = boost::program_options;

#define BENCH_DATA_MAGIC 0xEC6E4513
struct bench_data {
	const std::string *url;
	const std::string *url_report;
	long cycles_num;

	unsigned magic;
};


bool
ItsRegisterRequest_Process(const std::string url, const std::string url_es,
		ItsPkiInternalData &idata)
{
	ItsPkiSession session(idata);

        DEBUG_STREAM_CALLED;

        OCTETSTRING request;
        if (!session.ItsRegisterRequest_Create(idata, request))  {
                ERROR_STREAM << "Cannot compose ItsRegister request" << std::endl;
                return false;
        }
	dump_ttcn_object(request, "its register request: ");

        OCTETSTRING response_raw;
	if (!Curl_Send(url, url_es, idata.GetCanonicalId(), JSON, "operator:operator", request, response_raw))   {
                ERROR_STREAM << "request send error" << std::endl;
                return false;
	}
	dump_ttcn_object(response_raw, "its register response: ");
        
	OCTETSTRING cert_encoded;
        if (!session.ItsRegisterResponse_Parse(response_raw, cert_encoded))   {
                ERROR_STREAM << "cannot parse ItsRegister response" << std::endl;
                return false;
        }

        if (!session.ItsRegisterResponse_SaveToFiles(idata, cert_encoded))   {
                ERROR_STREAM << "Failed to save new ITS attributes to files" << std::endl;
                return false;
        }

        DEBUG_STREAM_RETURNS_OK;
        return true;
}


bool
EcEnrollmentRequest_Process(const std::string url_ea, const std::string url_es,
		ItsPkiInternalData &idata)
{
	ItsPkiSession session(idata);

        DEBUG_STREAM_CALLED;

        OCTETSTRING data_encrypted;
        if (!session.EcEnrollmentRequest_Create(idata, data_encrypted))   {
                ERROR_STREAM << "Create EC enrollment request failed" << std::endl;
                return false;
        }

        OCTETSTRING response_raw;
	if (!Curl_Send_ItsRequest(url_ea, url_es, idata.GetCanonicalId(), data_encrypted, response_raw))   {
                ERROR_STREAM << "request send error" << std::endl;
                return false;
	}

        OCTETSTRING cert_encoded;
        if (!session.EcEnrollmentResponse_Parse(response_raw, cert_encoded))   {
                ERROR_STREAM << "parse response error" << std::endl;
                return false;
        }

        if (!session.EcEnrollmentResponse_SaveToFiles(idata, cert_encoded))   {
                ERROR_STREAM << "Failed to save ITS EC certificate and/or ITS EC private keys" << std::endl;
                return false;
        }

        DEBUG_STREAM_RETURNS_OK;
        return true;
}


pthread_mutex_t thread_print_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t thread_counter_mutex = PTHREAD_MUTEX_INITIALIZER;
//static int exp_counter = 0;
static int thread_counter = 0;
// static long total_wait_period = 0;

pthread_mutex_t thread_parse_mutex = PTHREAD_MUTEX_INITIALIZER;

void *
ec_thread_handle(void *param)
{
        ItsPkiSession *session = (ItsPkiSession *)param;

	struct bench_data *b_data = (struct bench_data *) session->session_data;
	if (b_data == NULL || b_data->magic != BENCH_DATA_MAGIC)
		return NULL;

        pthread_mutex_lock (&thread_counter_mutex);
        int thread_idx = ++thread_counter;
        pthread_mutex_unlock (&thread_counter_mutex);

        ItsPkiInternalData *idata = session->GetIData();
        if (idata == NULL)   {
                std::cout << "Invalid IData" << std::endl;
                return NULL;
        }
	const std::string id = idata->GetCanonicalId();

        pthread_mutex_lock(&thread_print_mutex);
        std::cout << "In thread " << thread_idx << " do " << b_data->cycles_num << " cycles" << std::endl;
        pthread_mutex_unlock(&thread_print_mutex);

        for (int ii=0; ii < b_data->cycles_num; ii++)   {
                OCTETSTRING response_raw;
		if (!Curl_Send_ItsRequest(*(b_data->url), *(b_data->url_report), id, session->request_data, response_raw))   {
                        pthread_mutex_lock(&thread_print_mutex);
                        std::cout  << "thread " << thread_idx << ": send request error" << std::endl;
                        pthread_mutex_unlock(&thread_print_mutex);
                	continue;
		}

                pthread_mutex_lock(&thread_parse_mutex);
                bool res = session->EcEnrollmentResponse_Status(response_raw);
                pthread_mutex_unlock(&thread_parse_mutex);
                if (!res)   {
                        pthread_mutex_lock(&thread_print_mutex);
                        std::cout  << "thread " << thread_idx << ": response parse error" << std::endl;
                        pthread_mutex_unlock(&thread_print_mutex);
                        continue;
                }

        }

        return NULL;
}


bool
EcEnrollmentRequest_Bench(const std::string url_ea, const std::string url_es,
		long cycles_num, long threads_num,
		ItsPkiInternalData &idata)
{
        pthread_t request_threads[40];

	ItsPkiSession session(idata);
	struct bench_data b_data = {&url_ea, &url_es, cycles_num, BENCH_DATA_MAGIC};
	session.session_data = (void *)(&b_data);

        if ((unsigned)threads_num > sizeof(request_threads)/sizeof(request_threads[0]))   {
                threads_num = sizeof(request_threads)/sizeof(request_threads[0]);
		std::cout << "Number of threads is reduced to " << threads_num << std::endl;
        }

        thread_counter = 0;

        DEBUG_STREAM_CALLED;

        OCTETSTRING data_encrypted;
        if (!session.EcEnrollmentRequest_Create(idata, data_encrypted))   {
                ERROR_STREAM << "Create EC enrollment request failed" << std::endl;
                return false;
        }

        session.request_data = data_encrypted;
        for (int exp_cntr = 0; exp_cntr < 1; exp_cntr++)   {
                for (int ii = 0; ii < threads_num; ii++)   {
                        if(pthread_create(&request_threads[ii], NULL, ec_thread_handle, &session)) {
                                fprintf(stderr, "Error creating thread %i\n", ii);
                                return false;
                        }
                }

                for (int ii = 0; ii < threads_num; ii++)   {
                        void *thread_ret = NULL;
                        if(pthread_join(request_threads[ii], &thread_ret)) {
                                fprintf(stderr, "Cannot join thread %i\n", ii);
                                return false;
                        }
                }
        }
        std::cout << "All threads joined" << std::endl;

        DEBUG_STREAM_RETURNS_OK;
        return true;
}




bool
AtEnrollmentRequest_Process(const std::string url_at, const std::string url_es,
		ItsPkiInternalData &idata)
{
	ItsPkiSession session(idata);

        DEBUG_STREAM_CALLED;

        OCTETSTRING atRequest_encoded;
        if (!session.AtEnrollmentRequest_InnerAtRequest(idata, atRequest_encoded))  {
                ERROR_STREAM << "Cannot compose AT request" << std::endl;
                return false;
        }

        OCTETSTRING response_raw;
	if (!Curl_Send_ItsRequest(url_at, url_es, idata.GetCanonicalId(), atRequest_encoded, response_raw))   {
                ERROR_STREAM << "request send error" << std::endl;
                return false;
	}
        
	OCTETSTRING cert_encoded;
        if (!session.AtEnrollmentResponse_Parse(response_raw, cert_encoded))   {
                ERROR_STREAM << "cannot parse At Enrollment response" << std::endl;
                return false;
        }

        if (!session.AtEnrollmentResponse_SaveToFiles(idata, cert_encoded))   {
                ERROR_STREAM << "Failed to save ITS AT certificate or/and ITS AT keys" << std::endl;
                return false;
        }

        DEBUG_STREAM_RETURNS_OK;
        return true;
}


bool
ParseEcEnrollmentCmdArguments(ItsPkiCmdArguments cmd_args, ItsPkiInternalData &idata)
{
	DEBUG_STREAM_CALLED;

	// ITS Technical Key
	void *key = NULL;
	if (!cmd_args.its_tkey.empty())
		key = ECKey_ReadPrivateKey(cmd_args.its_tkey.c_str());	
	else if (!cmd_args.its_tkey_b64.empty())
		key = ECKey_ReadPrivateKeyB64(cmd_args.its_tkey_b64.c_str());	
	if (!idata.SetItsTechnicalKey(key))   {
		ERROR_STREAM << "EC enroll: Missing or invalid technical key" << std::endl;
		return false;
	}
	
	// ITS Ec Encryption Key
	if (cmd_args.its_ec_ekey_enable)   {
		key = NULL;
		if (!cmd_args.its_ec_ekey.empty())
			key = ECKey_ReadPrivateKey(cmd_args.its_ec_ekey.c_str()); 
		else if (!cmd_args.its_ec_ekey_b64.empty())
			key = ECKey_ReadPrivateKeyB64(cmd_args.its_ec_ekey_b64.c_str()); 
		else 
			key = ECKey_GeneratePrivateKey();
		idata.SetItsEcEncryptionKey(key);
	}

	// ITS Ec Verification Key
	key = NULL;
	if (!cmd_args.its_ec_vkey.empty())
		key = ECKey_ReadPrivateKey(cmd_args.its_ec_vkey.c_str()); 
	else if (!cmd_args.its_ec_vkey_b64.empty())
		key = ECKey_ReadPrivateKeyB64(cmd_args.its_ec_vkey_b64.c_str()); 
	else
		key = ECKey_GeneratePrivateKey();
	idata.SetItsEcVerificationKey(key);

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

	// Create/Set ITS canonical ID
	if (!idata.SetCanonicalID(cmd_args.its_canonical_id, cmd_args.its_name_header, idata.GetItsTechnicalKey()))   {
		ERROR_STREAM << "EC enroll arguments: cannot set ITS canonical ID" << std::endl;
		return false;
	}
	DEBUG_STREAM << "ITS Canonical ID: '" << idata.GetCanonicalId() << "'" << std::endl;

	// Set permissions
	if (!idata.SetAidSsp(cmd_args.app_perms_psid, cmd_args.app_perms_ssp_opaque, cmd_args.app_perms_ssp_bitmap))   {
		ERROR_STREAM << "EC enroll arguments: cannot set ITS AID SSP list" << std::endl;
		return false;
	}
	DEBUG_STREAM << "ITS AID SSP(id=" << idata.GetAppPermsSsp().psid << ",tag=" << idata.GetAppPermsSsp().type << ",ssp=" << oct2str(idata.GetAppPermsSsp().ssp) << ")" << std::endl;

	// Set ITS Hash algorithm
	if (!idata.SetHashAlgorithm(cmd_args.GetHashAlgorithm()))   {
		ERROR_STREAM << "EC enroll arguments: cannot set Hash algorithm" << std::endl;
		return false;
	}

	// Save enrollment results: ITS EC certificate and verification key
	if (cmd_args.its_ec_cert_save2file.empty())
		idata.SetItsEcCertSave2File(idata.GetCanonicalId() + "-EC-cert.oer");
	else
		idata.SetItsEcCertSave2File(cmd_args.its_ec_certfile);
	
	if (cmd_args.its_ec_vkey_save2file.empty())
		idata.SetItsEcVerificationKeySave2File(idata.GetCanonicalId() + "-EC-vkey.pem");
	else
		idata.SetItsEcVerificationKeySave2File(cmd_args.its_ec_vkey_save2file);

	// Save enrollment results: ITS EC encryption key
	if (cmd_args.its_ec_ekey_enable)   {
		if (cmd_args.its_ec_ekey_save2file.empty())
			idata.SetItsEcEncryptionKeySave2File(idata.GetCanonicalId() + "-EC-ekey.pem");
		else
			idata.SetItsEcEncryptionKeySave2File(cmd_args.its_ec_ekey_save2file);
	}

	DEBUG_STREAM_RETURNS_OK;
	return true;
}


bool
ParseAtEnrollmentCmdArguments(ItsPkiCmdArguments cmd_args, ItsPkiInternalData &idata)
{
	DEBUG_STREAM_CALLED;
	
	void *key = NULL;
	if (!cmd_args.its_at_vkey.empty())
		key = ECKey_ReadPrivateKey(cmd_args.its_at_vkey.c_str()); 
	else if (!cmd_args.its_at_vkey_b64.empty())
		key = ECKey_ReadPrivateKeyB64(cmd_args.its_at_vkey_b64.c_str()); 
	else
		key = ECKey_GeneratePrivateKey();
	if (!idata.SetItsAtVerificationKey(key))   {
		ERROR_STREAM << "AT enroll: cannot read from file, base64 string or generate the AT verification key "<< std::endl;
		return false;
	}

	if (cmd_args.its_at_ekey_enable)   {
		key = NULL;
		if (!cmd_args.its_at_ekey.empty())
			key = ECKey_ReadPrivateKey(cmd_args.its_at_ekey.c_str()); 
		else
			key = ECKey_GeneratePrivateKey();
		if (!idata.SetItsAtEncryptionKey(key))   {
			ERROR_STREAM << "At enroll: cannot read from file or generate ITS AT encryption key "<< std::endl;
			return false;
		}
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
	
	// Set permissions
	if (!idata.SetAidSsp(cmd_args.app_perms_psid, cmd_args.app_perms_ssp_opaque, cmd_args.app_perms_ssp_bitmap))   {
		ERROR_STREAM << "EC enroll arguments: cannot set ITS AID SSP list" << std::endl;
		return false;
	}
	DEBUG_STREAM << "ITS AID SSP(id=" << idata.GetAppPermsSsp().psid << ",tag=" << idata.GetAppPermsSsp().type << ",ssp=" << oct2str(idata.GetAppPermsSsp().ssp) << ")" << std::endl;

	// Set ITS Hash algorithm
	if (!idata.SetHashAlgorithm(cmd_args.GetHashAlgorithm()))   {
		ERROR_STREAM << "EC enroll arguments: cannot set Hash algorithm" << std::endl;
		return false;
	}

	// Save enrollment results: ITS AT certificate and verification key
	if (!cmd_args.its_at_cert_save2file.empty())
		idata.SetItsAtCertSave2File(cmd_args.its_at_certfile);
	else if (!idata.GetCanonicalId().empty())
		idata.SetItsAtCertSave2File(idata.GetCanonicalId() + "-AT-cert.oer");

	if (!cmd_args.its_at_vkey_save2file.empty())
		idata.SetItsAtVerificationKeySave2File(cmd_args.its_at_vkey_save2file);
	else if (!idata.GetCanonicalId().empty())
		idata.SetItsAtVerificationKeySave2File(idata.GetCanonicalId() + "-AT-vkey.pem");

	// Save enrollment results: ITS AT encryption key
	if (cmd_args.its_at_ekey_enable)   {
		if (!cmd_args.its_at_ekey_save2file.empty())
			idata.SetItsAtEncryptionKeySave2File(cmd_args.its_at_ekey_save2file);
		else if (!idata.GetCanonicalId().empty())
			idata.SetItsAtEncryptionKeySave2File(idata.GetCanonicalId() + "-AT-ekey.pem");
	}

	DEBUG_STREAM_RETURNS_OK;
        return true;
}


bool
ParseItsRegisterCmdArguments(ItsPkiCmdArguments cmd_args, ItsPkiInternalData &idata)
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
	else
		key = ECKey_GeneratePrivateKey();
	if (!idata.SetItsTechnicalKey(key))   {
		ERROR_STREAM << "EC enroll: Missing or invalid technical key" << std::endl;
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


