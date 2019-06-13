#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>
#include <boost/program_options.hpp>

#include "TTCN3.hh"
#include "EtsiTs103097Module.hh"

#include "its/pki-its-debug.hh"
#include "its/pki-its-cmd-args.hh"
#include "its/pki-its-internal-data.hh"
#include "its/pki-its-work.hh"
#include "its/utils.hh"

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
EcEnrollmentRequest_Process(const std::string url_ea, const std::string url_es,
		ItsPkiInternalData &idata)
{
	ItsPkiWork work(idata);

        DEBUG_STREAM_CALLED;

        OCTETSTRING data_encrypted;
        if (!work.EcEnrollmentRequest_Create(idata, data_encrypted))   {
                ERROR_STREAM << "Create EC enrollment request failed" << std::endl;
                return false;
        }

        OCTETSTRING response_raw;
	if (!Curl_Send(url_ea, url_es, idata.GetCanonicalId(), data_encrypted, response_raw))   {
                ERROR_STREAM << "request send error" << std::endl;
                return false;
	}

        OCTETSTRING cert_encoded;
        if (!work.EcEnrollmentResponse_Parse(response_raw, cert_encoded))   {
                ERROR_STREAM << "parse response error" << std::endl;
                return false;
        }

        if (!work.EcEnrollmentResponse_SaveToFiles(idata, cert_encoded))   {
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
        ItsPkiWork *work = (ItsPkiWork *)param;

	struct bench_data *b_data = (struct bench_data *) work->work_data;
	if (b_data == NULL || b_data->magic != BENCH_DATA_MAGIC)
		return NULL;

        pthread_mutex_lock (&thread_counter_mutex);
        int thread_idx = ++thread_counter;
        pthread_mutex_unlock (&thread_counter_mutex);

        ItsPkiInternalData *idata = work->GetIData();
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
		if (!Curl_Send(*(b_data->url), *(b_data->url_report), id, work->request_data, response_raw))   {
                        pthread_mutex_lock(&thread_print_mutex);
                        std::cout  << "thread " << thread_idx << ": send request error" << std::endl;
                        pthread_mutex_unlock(&thread_print_mutex);
                	continue;
		}

                pthread_mutex_lock(&thread_parse_mutex);
                bool res = work->EcEnrollmentResponse_Status(response_raw);
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

	ItsPkiWork work(idata);
	struct bench_data b_data = {&url_ea, &url_es, cycles_num, BENCH_DATA_MAGIC};
	work.work_data = (void *)(&b_data);

        if ((unsigned)threads_num > sizeof(request_threads)/sizeof(request_threads[0]))   {
                threads_num = sizeof(request_threads)/sizeof(request_threads[0]);
		std::cout << "Number of threads is reduced to " << threads_num << std::endl;
        }

        thread_counter = 0;

        DEBUG_STREAM_CALLED;

        OCTETSTRING data_encrypted;
        if (!work.EcEnrollmentRequest_Create(idata, data_encrypted))   {
                ERROR_STREAM << "Create EC enrollment request failed" << std::endl;
                return false;
        }

        work.request_data = data_encrypted;
        for (int exp_cntr = 0; exp_cntr < 1; exp_cntr++)   {
                for (int ii = 0; ii < threads_num; ii++)   {
                        if(pthread_create(&request_threads[ii], NULL, ec_thread_handle, &work)) {
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
	ItsPkiWork work(idata);

        DEBUG_STREAM_CALLED;

        OCTETSTRING atRequest_encoded;
        if (!work.AtEnrollmentRequest_InnerAtRequest(idata, atRequest_encoded))  {
                ERROR_STREAM << "Cannot compose AT request" << std::endl;
                return false;
        }

        OCTETSTRING response_raw;
	if (!Curl_Send(url_at, url_es, idata.GetCanonicalId(), atRequest_encoded, response_raw))   {
                ERROR_STREAM << "request send error" << std::endl;
                return false;
	}
        
	OCTETSTRING cert_encoded;
        if (!work.AtEnrollmentResponse_Parse(response_raw, cert_encoded))   {
                ERROR_STREAM << "cannot parse At Enrollment response" << std::endl;
                return false;
        }

        if (!work.AtEnrollmentResponse_SaveToFiles(idata, cert_encoded))   {
                ERROR_STREAM << "Failed to save ITS AT certificate or/and ITS AT keys" << std::endl;
                return false;
        }

        DEBUG_STREAM_RETURNS_OK;
        return true;
}


int
__main(int argc, const char *argv[])
{
	ItsPkiCmdArguments cmd_args(argc, argv);
	
	if (!cmd_args.ValidateOperation())   {
		std::cerr << "Invalid command argument: '" << cmd_args.GetLastErrorString() << "'" << std::endl;
	}
	else if (cmd_args.IsCmdHelp())  {
		cmd_args.PrintHelp(std::cout);
		std::cerr << "Enable: '" << cmd_args.its_ec_ekey_enable << "'" << std::endl;
	}
	else if (cmd_args.IsCmdInfo())   {
		OCTETSTRING os_18;
		if (!read_bytes(cmd_args.GetInputFile(), os_18))   {
			std::cerr << "Cannot read data from file '" << cmd_args.GetInputFile() << "'" << std::endl;
			exit(-1);
		}

		EtsiTs103097Module::module_object.pre_init_module();
        	IEEE1609dot2::CertificateBase ret = decEtsiTs103097Certificate(os_18);
		std::cout << "IEEE1609dot2::CertificateBase::Version " << ret.version() << std::endl;

		if (cmd_args.IsFormatJson())   {
			TTCN_Logger::begin_event(TTCN_Logger::USER_UNQUALIFIED, 1);
			ret.log();
			char *res_log = TTCN_Logger::end_event_log2str().to_JSON_string();
			std::cout << "TTCN-log:\n" << res_log << "\n\n";
			Free(res_log);
		}
		else if (cmd_args.IsFormatYaml())   {
			YAML::Emitter yaml;
			yaml << YAML::BeginMap << YAML::Key << "EtsiTs103097Certificate" << YAML::Value;
			ret.YAML_emitter_write(yaml);
			yaml << YAML::EndMap;
			std::cout << "YAML:" << std::endl << yaml.c_str() << std::endl << std::flush;
		}
	}
	else   {
		do   {
			ItsPkiInternalData idata(cmd_args);
			if (!idata.IsValid())
				break;

			if (cmd_args.IsCmdItsRegister())   {
				ItsPkiWork work(idata);

				if (!work.ItsRegister(idata))
					std::cerr << "Fatal error of ITS registration" << std::endl;
			}
			else if (cmd_args.IsCmdEcEnrollRequest())   {
				if (cmd_args.IsBench())   {
					if (!EcEnrollmentRequest_Bench(cmd_args.url_ea, cmd_args.url_es, cmd_args.cycles_num, cmd_args.threads_num, idata))
						std::cerr << "Fatal error of Ec Enrollment Request Bench" << std::endl;
				}
				else   {
					if (!EcEnrollmentRequest_Process(cmd_args.url_ea, cmd_args.url_es, idata))
						std::cerr << "Fatal error of Ec Enrollment Request" << std::endl;
				}
			}
			else if (cmd_args.IsCmdAtEnrollRequest())   {
				if (!AtEnrollmentRequest_Process(cmd_args.url_aa, cmd_args.url_es, idata))
					std::cerr << "Fatal error of AT Enrollment Request" << std::endl;
			}
		} while(0);
	}
	
	TTCN_Logger::clear_parameters();
	TTCN_EncDec::clear_error();
	TTCN_Logger::terminate_logger();
	TTCN_Snapshot::terminate();
	TTCN_Runtime::clean_up();
	return 0;
}
