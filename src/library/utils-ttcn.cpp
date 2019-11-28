// https://gist.github.com/a2e0040d301bf4b8ef8101c0b1e3f1d5.git
#include <string>
#include <iostream>
#include <memory>
#include <cstdio>

#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "its/utils-openssl.hh"
#include "its/utils-ttcn.hh"
#include "its/itspki-debug.hh"

pthread_mutex_t mutex_encode_request = PTHREAD_MUTEX_INITIALIZER;

#ifdef ITS_PKI_DEBUG 
bool
dump_ttcn_object(Base_Type &obj, const char *title)
{
	TTCN_Logger::begin_event(TTCN_Logger::USER_UNQUALIFIED, 1);
	obj.log();
	char *res_log = TTCN_Logger::end_event_log2str().to_JSON_string();
	std::cout << title << res_log << std::endl;
	Free(res_log);
	return true;
}
#else
bool
dump_ttcn_object(Base_Type &, const char *)
{
	return true;
}
#endif


bool
getEtsiTs103097CertId(OCTETSTRING &cert_raw, OCTETSTRING &ret_certId)
{
        DEBUG_STREAM_CALLED;

        IEEE1609dot2::module_object.pre_init_module();
        IEEE1609dot2BaseTypes::module_object.pre_init_module();

        IEEE1609dot2::CertificateBase cert = decEtsiTs103097Certificate(cert_raw);

        IEEE1609dot2::VerificationKeyIndicator vKeyIndicator = cert.toBeSigned().verifyKeyIndicator();
        if (!vKeyIndicator.ischosen(IEEE1609dot2::VerificationKeyIndicator::ALT_verificationKey))   {
                ERROR_STREAM << "ItsPkiInternalData::SetCertID() not supported type of VerificationKeyIndicator" << std::endl;
                return false;
        }

        IEEE1609dot2BaseTypes::PublicVerificationKey pubKey = vKeyIndicator.verificationKey();
        if (pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaNistP256) ||
                        pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaBrainpoolP256r1))   {
                if (!OpenSSL_SHA256_HashedID(cert_raw, ret_certId))   {
                        ERROR_STREAM << "ItsPkiInternalData::SetCertID() OpenSSL SHA256 HashedID failed" << std::endl;
                        return false;
                }
        }
        else if (pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaBrainpoolP384r1))   {
                if (!OpenSSL_SHA384_HashedID(cert_raw, ret_certId))   {
                        ERROR_STREAM << "ItsPkiInternalData::SetCertID() OpenSSL SHA384 HashedID failed" << std::endl;
                        return false;
                }
        }
        else   {
                ERROR_STREAM << "ItsPkiInternalData::setEncryptionKey() not supported PublicVerificationKey type" << std::endl;
                return false;
        }

        DEBUG_STREAM_RETURNS_OK;
        return true;
}


IEEE1609dot2::CertificateBase
decEtsiTs103097Certificate(const OCTETSTRING& stream)
{       
        TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_DEFAULT);
        TTCN_EncDec::clear_error();
        TTCN_Buffer ttcn_buffer(stream);

        IEEE1609dot2::CertificateBase ret_val;
        ret_val.decode(EtsiTs103097Module::EtsiTs103097Certificate_descr_, ttcn_buffer, TTCN_EncDec::CT_OER);

        if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
                TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
                TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Decoded @IEEE1609dot2.CertificateBase: ");
                ret_val.log();
                TTCN_Logger::end_event();
        }

        if (TTCN_EncDec::get_last_error_type() == TTCN_EncDec::ET_NONE) {
                if (ttcn_buffer.get_pos() < ttcn_buffer.get_len() && TTCN_Logger::log_this_event(TTCN_WARNING)) {
                        ttcn_buffer.cut();
                        OCTETSTRING remaining_stream;
                        ttcn_buffer.get_string(remaining_stream);
                        TTCN_Logger::begin_event(TTCN_WARNING);
                        TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Warning: Data remained at the end of the stream after successful decoding: ");
                        remaining_stream.log();
                        TTCN_Logger::end_event();
                }
        }

        return ret_val;
}


IEEE1609dot2::Ieee1609Dot2Data
decIeee1609Dot2Data(const OCTETSTRING& stream)
{       
        TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_DEFAULT);
        TTCN_EncDec::clear_error();
        TTCN_Buffer ttcn_buffer(stream);

	IEEE1609dot2::Ieee1609Dot2Data ret_val;
	if (ret_val.get_descriptor() !=NULL)
        	ret_val.decode(*(ret_val.get_descriptor()), ttcn_buffer, TTCN_EncDec::CT_OER);

        if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
                TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
                TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Decoded @IEEE1609dot2.CertificateBase: ");
                ret_val.log();
                TTCN_Logger::end_event();
        }

        if (TTCN_EncDec::get_last_error_type() == TTCN_EncDec::ET_NONE) {
                if (ttcn_buffer.get_pos() < ttcn_buffer.get_len() && TTCN_Logger::log_this_event(TTCN_WARNING)) {
                        ttcn_buffer.cut();
                        OCTETSTRING remaining_stream;
                        ttcn_buffer.get_string(remaining_stream);
                        TTCN_Logger::begin_event(TTCN_WARNING);
                        TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Warning: Data remained at the end of the stream after successful decoding: ");
                        remaining_stream.log();
                        TTCN_Logger::end_event();
                }
        }

        return ret_val;
}


EtsiTs103097Module::EtsiTs103097Data__Signed__My
decEtsiTs103097DataSigned(const OCTETSTRING& stream)
{       
        TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_DEFAULT);
        TTCN_EncDec::clear_error();
        TTCN_Buffer ttcn_buffer(stream);

	EtsiTs103097Module::EtsiTs103097Data__Signed__My ret_val;
	if (ret_val.get_descriptor() !=NULL)
        	ret_val.decode(*(ret_val.get_descriptor()), ttcn_buffer, TTCN_EncDec::CT_OER);

        if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
                TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
                TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Decoded @IEEE1609dot2.CertificateBase: ");
                ret_val.log();
                TTCN_Logger::end_event();
        }

        if (TTCN_EncDec::get_last_error_type() == TTCN_EncDec::ET_NONE) {
                if (ttcn_buffer.get_pos() < ttcn_buffer.get_len() && TTCN_Logger::log_this_event(TTCN_WARNING)) {
                        ttcn_buffer.cut();
                        OCTETSTRING remaining_stream;
                        ttcn_buffer.get_string(remaining_stream);
                        TTCN_Logger::begin_event(TTCN_WARNING);
                        TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Warning: Data remained at the end of the stream after successful decoding: ");
                        remaining_stream.log();
                        TTCN_Logger::end_event();
                }
        }

        return ret_val;
}

EtsiTs102941MessagesCa::EtsiTs102941Data
decEtsiTs102941Data(const OCTETSTRING& stream)
{
        TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_DEFAULT);
        TTCN_EncDec::clear_error();
        TTCN_Buffer ttcn_buffer(stream);

	EtsiTs102941MessagesCa::EtsiTs102941Data ret_val;
	if (ret_val.get_descriptor() !=NULL)
        	ret_val.decode(*(ret_val.get_descriptor()), ttcn_buffer, TTCN_EncDec::CT_OER);

        if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
                TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
                TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Decoded @IEEE1609dot2.CertificateBase: ");
                ret_val.log();
                TTCN_Logger::end_event();
        }

        if (TTCN_EncDec::get_last_error_type() == TTCN_EncDec::ET_NONE) {
                if (ttcn_buffer.get_pos() < ttcn_buffer.get_len() && TTCN_Logger::log_this_event(TTCN_WARNING)) {
                        ttcn_buffer.cut();
                        OCTETSTRING remaining_stream;
                        ttcn_buffer.get_string(remaining_stream);
                        TTCN_Logger::begin_event(TTCN_WARNING);
                        TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Warning: Data remained at the end of the stream after successful decoding: ");
                        remaining_stream.log();
                        TTCN_Logger::end_event();
                }
        }

        return ret_val;
}

EtsiTs102941TypesAuthorization::InnerAtResponse
decInnerAtResponse(const OCTETSTRING &stream)
{
        TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_DEFAULT);
        TTCN_EncDec::clear_error();
        TTCN_Buffer ttcn_buffer(stream);

	EtsiTs102941TypesAuthorization::InnerAtResponse ret_val;
	if (ret_val.get_descriptor() !=NULL)
        	ret_val.decode(*(ret_val.get_descriptor()), ttcn_buffer, TTCN_EncDec::CT_OER);

        if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
                TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
                TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Decoded @IEEE1609dot2.CertificateBase: ");
                ret_val.log();
                TTCN_Logger::end_event();
        }

        if (TTCN_EncDec::get_last_error_type() == TTCN_EncDec::ET_NONE) {
                if (ttcn_buffer.get_pos() < ttcn_buffer.get_len() && TTCN_Logger::log_this_event(TTCN_WARNING)) {
                        ttcn_buffer.cut();
                        OCTETSTRING remaining_stream;
                        ttcn_buffer.get_string(remaining_stream);
                        TTCN_Logger::begin_event(TTCN_WARNING);
                        TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Warning: Data remained at the end of the stream after successful decoding: ");
                        remaining_stream.log();
                        TTCN_Logger::end_event();
                }
        }
	
	return ret_val;
}


EtsiTs103097Module::EtsiTs103097Data__Encrypted__My
decEtsiTs103097DataEncrypted(const OCTETSTRING &stream)
{
        TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_DEFAULT);
        TTCN_EncDec::clear_error();
        TTCN_Buffer ttcn_buffer(stream);

	EtsiTs103097Module::EtsiTs103097Data__Encrypted__My ret_val;
	if (ret_val.get_descriptor() !=NULL)
        	ret_val.decode(*(ret_val.get_descriptor()), ttcn_buffer, TTCN_EncDec::CT_OER);

        if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
                TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
                TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Decoded @IEEE1609dot2.CertificateBase: ");
                ret_val.log();
                TTCN_Logger::end_event();
        }

        if (TTCN_EncDec::get_last_error_type() == TTCN_EncDec::ET_NONE) {
                if (ttcn_buffer.get_pos() < ttcn_buffer.get_len() && TTCN_Logger::log_this_event(TTCN_WARNING)) {
                        ttcn_buffer.cut();
                        OCTETSTRING remaining_stream;
                        ttcn_buffer.get_string(remaining_stream);
                        TTCN_Logger::begin_event(TTCN_WARNING);
                        TTCN_Logger::log_event_str("dec_EtsiTs103097Certificate(): Warning: Data remained at the end of the stream after successful decoding: ");
                        remaining_stream.log();
                        TTCN_Logger::end_event();
                }
        }
	
	return ret_val;

}


std::string
printableItsCanonicalId(const OCTETSTRING &cid)
{
        std::string ret;
        int ii = 0;

        for (ii=0; ii<cid.lengthof(); ii++)   {
                char c = (char) (cid[ii].get_octet());
                if ( std::isalnum(c) || c == '-')   {
                        ret += c;
                }
                else   {
                        break;
                }
        }

        if (ii<cid.lengthof())   {
                OCTETSTRING sid = OCTETSTRING(cid.lengthof() - ii, (const unsigned char *)cid + ii);
                ret += '.';
                ret += std::string(oct2str(sid));
        }

        return ret;
}
