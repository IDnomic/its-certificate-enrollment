#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>
#include <boost/program_options.hpp>
#include <memory>
 
#include <openssl/ec.h>
#include <openssl/err.h>
#include "openssl/conf.h"
#include "openssl/err.h"
#include "openssl/engine.h"
#include "openssl/ssl.h"

#include "TTCN3.hh"
#include "EtsiTs103097Module.hh"
#include "EtsiTs102941MessagesCa.hh"

#include "its/utils.hh"
#include "its/itspki-debug.hh"
#include "its/itspki-session.hh"
#include "its/itspki-etsi.hh"


bool ItsPkiException::initialized = false;

ItsPkiSession::ItsPkiSession(ItsPkiInternalData &_idata)
{
	TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_DEFAULT);
	TTCN_EncDec::clear_error();
	
	idata = &_idata;
}


ItsPkiSession::~ItsPkiSession()
{
        ECKey_Free(sessionTechnicalKey);
        ECKey_Free(sessionItsEcVerificationKey);
        ECKey_Free(sessionItsEcEncryptionKey);
        ECKey_Free(sessionItsAtVerificationKey);
        ECKey_Free(sessionItsAtEncryptionKey);
	OpenSSL_cleanup();
}


bool
ItsPkiSession::GetPublicVerificationKey(void *ec_key, IEEE1609dot2BaseTypes::PublicVerificationKey &pubkey)
{
        int nid = -1;
        OCTETSTRING x, y;

        DEBUGC_STREAM_CALLED;
        if (!ECKey_GetPublicKeyComponents(ec_key, nid, x, y))   {
                ERROR_STREAMC << "something wrong with EC PublicKey components" << std::endl;
                return false;
        }

        if (nid == NID_X9_62_prime256v1)   {
                IEEE1609dot2BaseTypes::EccP256CurvePoint ec_point;
                ec_point.uncompressedP256().x() = x;
                ec_point.uncompressedP256().y() = y;
                pubkey.ecdsaNistP256() = ec_point;
        }
        else if (nid == NID_brainpoolP256r1)   {
                IEEE1609dot2BaseTypes::EccP256CurvePoint ec_point;
                ec_point.uncompressedP256().x() = x;
                ec_point.uncompressedP256().y() = y;
                pubkey.ecdsaBrainpoolP256r1() = ec_point;
        }
        else if (nid == NID_brainpoolP384r1)   {
                IEEE1609dot2BaseTypes::EccP384CurvePoint ec_point;
                ec_point.uncompressedP384().x() = x;
                ec_point.uncompressedP384().y() = y;
                pubkey.ecdsaBrainpoolP384r1() = ec_point;
        }
        else    {
                ERROR_STREAMC << "no support for EC curve '" << OBJ_nid2sn(nid) << "'" << std::endl;
                return false;
        }

        DEBUGC_STREAM_RETURNS_OK;
        return true;
}


bool
ItsPkiSession::GetItsEcPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &pubkey)
{
	if (idata == NULL)
		return false;
	void *key = idata->GetItsEcVerificationKey();
	if (key == NULL)
		key = sessionItsEcVerificationKey;
	if (key == NULL)
		return false;

        return GetPublicVerificationKey(key, pubkey);
}


bool
ItsPkiSession::GetItsAtPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &pubkey)
{
        DEBUGC_STREAM_CALLED;

	if (idata == NULL)
		return false;
	void *key = idata->GetItsAtVerificationKey();
	if (key == NULL)
		key = sessionItsAtVerificationKey;
	if (key == NULL)
		return false;

        return GetPublicVerificationKey(key, pubkey);
}


bool
ItsPkiSession::GetPublicEncryptionKey(void *ec_key, IEEE1609dot2BaseTypes::PublicEncryptionKey &pubkey)
{
        int nid = -1;
        OCTETSTRING x, y;

        DEBUGC_STREAM_CALLED;

        if (!ECKey_GetPublicKeyComponents(ec_key, nid, x, y))   {
                ERROR_STREAMC << "something wrong with EC PublicKey components" << std::endl;
                return false;
        }

        if (nid == NID_X9_62_prime256v1)   {
                IEEE1609dot2BaseTypes::EccP256CurvePoint ec_point;
                ec_point.uncompressedP256().x() = x;
                ec_point.uncompressedP256().y() = y;
                pubkey.publicKey().eciesNistP256() = ec_point;
        }
        else if (nid == NID_brainpoolP256r1)   {
                IEEE1609dot2BaseTypes::EccP256CurvePoint ec_point;
                ec_point.uncompressedP256().x() = x;
                ec_point.uncompressedP256().y() = y;
                pubkey.publicKey().eciesBrainpoolP256r1() = ec_point;
        }
        else    {
                ERROR_STREAMC << "unexpected EC curve: " << OBJ_nid2sn(nid) << std::endl;
                return false;
        }

        pubkey.supportedSymmAlg() = IEEE1609dot2BaseTypes::SymmAlgorithm::aes128Ccm;

        DEBUGC_STREAM_RETURNS_OK;
        return true;
}


bool
ItsPkiSession::GetItsEcPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &pubkey)
{
	if (idata == NULL)
		return false;
	void *key = idata->GetItsEcEncryptionKey();
	if (key == NULL)
		key = sessionItsEcEncryptionKey;
	if (key == NULL)
		return false;

        return GetPublicEncryptionKey(key, pubkey);
}


bool
ItsPkiSession::GetItsAtPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &pubkey)
{
        DEBUGC_STREAM_CALLED;

	if (idata == NULL)
		return false;
	void *key = idata->GetItsAtEncryptionKey();
	if (key == NULL)
		key = sessionItsAtEncryptionKey;
	if (key == NULL)
		return false;

        return GetPublicEncryptionKey(key, pubkey);
}


OCTETSTRING &
ItsPkiSession::sessionGetItsEcCert()
{
	if (idata != NULL && idata->GetItsEcCertBlob().is_bound())
		return idata->GetItsEcCertBlob();
	return sessionItsEcCert;
};


OCTETSTRING &
ItsPkiSession::sessionGetItsEcId()
{
	if (idata != NULL && idata->GetItsEcId().is_bound())
		return idata->GetItsEcId();
	return sessionItsEcId;
};


bool
ItsPkiSession::GetIEEE1609dot2Signature(ItsPkiInternalData &idata, OCTETSTRING &data, OCTETSTRING &signer, void *key,
		IEEE1609dot2BaseTypes::Signature &out_signature)
{
	DEBUGC_STREAM_CALLED;

	if (key == NULL)   {
		ERROR_STREAMC << "invalid argument: no key" << std::endl;
		return false;
	}

	int nid = ECKey_GetNid(key);

	OCTETSTRING rSig, sSig;
	if (!idata.IEEE1609dot2_Sign(data, signer, key, rSig, sSig))   {
		ERROR_STREAMC << "Signature failed" << std::endl;
		return false;
	}

	dump_ttcn_object(rSig, "Signature::rSig: ");
	dump_ttcn_object(sSig, "Signature::sSig: ");

	DEBUGC_STREAM << "nid '" << OBJ_nid2sn(nid) << "'" << std::endl;
	if (nid == NID_X9_62_prime256v1)   {
                IEEE1609dot2BaseTypes::EccP256CurvePoint curve_point;
                curve_point.x__only() = rSig;

                IEEE1609dot2BaseTypes::EcdsaP256Signature signature;
                signature.rSig() = curve_point;
                signature.sSig() = sSig;

		out_signature.ecdsaNistP256Signature() = signature;
	}
	else if (nid == NID_brainpoolP256r1)  {
                IEEE1609dot2BaseTypes::EccP256CurvePoint curve_point;
                curve_point.x__only() = rSig;

                IEEE1609dot2BaseTypes::EcdsaP256Signature signature;
                signature.rSig() = curve_point;
                signature.sSig() = sSig;

		out_signature.ecdsaBrainpoolP256r1Signature() = signature;
	}
	else if (nid == NID_brainpoolP384r1)   {
                IEEE1609dot2BaseTypes::EccP384CurvePoint curve_point;
                curve_point.x__only() = rSig;

                IEEE1609dot2BaseTypes::EcdsaP384Signature signature;
                signature.rSig() = curve_point;
                signature.sSig() = sSig;

		out_signature.ecdsaBrainpoolP384r1Signature() = signature;
	}
	else   {
		ERROR_STREAMC << "non supported EC curve '" << OBJ_nid2sn(nid) << "'"  << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiSession::ItsRegisterRequest_Create(ItsPkiInternalData &idata, OCTETSTRING &ret)
{
        DEBUGC_STREAM_CALLED;

	if (!idata.CheckItsRegisterData())   {
                ERROR_STREAMC << "invalid Its registration internal data" << std::endl;
                return false;
        }
	
	void *t_key = idata.GetItsTechnicalKey();
	if (t_key == NULL)   {
		if (sessionTechnicalKey == NULL)
			sessionTechnicalKey = ECKey_GeneratePrivateKey(); 
		t_key = sessionTechnicalKey;
	}

	if (t_key == NULL)   {
                ERROR_STREAMC << "No ITS Technical key" << std::endl;
                return false;
	}

        unsigned char *key_b64 = NULL;
        size_t key_b64_len = 0;

        if (!ECKey_PublicKeyToMemory(t_key, &key_b64, &key_b64_len))   {
                ERROR_STREAMC << "cannot write public key to memory" << std::endl;
                return false;
        }

	std::string request_str = std::string("{")
                + "\"canonicalId\":\"" + sessionGetCanonicalId(idata) + "\","
                + "\"profile\":\"" + idata.GetProfile() + "\","
                + "\"technicalPublicKey\":\"" + (char *)key_b64 + "\","
                + "\"status\":\"ACTIVATED\""
                + "}";

        free(key_b64);
        key_b64 = NULL;

	ret = OCTETSTRING(request_str.length(), (const unsigned char *)request_str.c_str());

        DEBUGC_STREAM_RETURNS_OK;
	return true;
}




bool
ItsPkiSession::ItsRegisterResponse_Parse(OCTETSTRING &response_raw, OCTETSTRING &ret_cert)
{
	DEBUGC_STREAM_CALLED;

	// TODO: parse properly...
	OCTETSTRING decoded = str2oct(oct2str(response_raw));
	std::string resp((const char *)((const unsigned char *)decoded), decoded.lengthof());

	if (!json_get_tag_value(resp, "id", its_id))   {
		ERROR_STREAMC << "Invalid ITS registration response: no 'id' tag" << std::endl;
		return false;
	}
#if 0
	else if (its_id.find_first_not_of( "0123456789" ) != std::string::npos)   {
		ERROR_STREAMC << "Invalid ITS registration response: invalid id: '" << its_id << "" << std::endl;
		return false;
	}
#endif
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiSession::ItsRegisterResponse_SaveToFiles(ItsPkiInternalData &idata, OCTETSTRING &request)
{
	DEBUGC_STREAM_CALLED;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


std::string
ItsPkiSession::sessionGetCanonicalId(ItsPkiInternalData &idata)
{
	DEBUGC_STREAM_CALLED;

	std::string ret = idata.GetCanonicalId();
	if (!ret.empty())
		return ret;

	void *key = sessionGetTechnicalKey();
	if (key == NULL)   {
		ERROR_STREAMC << "failed: no ITS Technical Key" << std::endl;
		return ret;
	}

        OCTETSTRING h;
	if (!ECKey_PublicKeyHashedID(key, h))   {
		ERROR_STREAMC << "cannot get HashedID from EC public key" << std::endl;
		return ret;
							        
	}

	ret = string_format("%s-%02X%02X%02X%02X%02X%02X%02X%02X", idata.GetItsNameHeader().c_str(),
			h[0].get_octet(), h[1].get_octet(), h[2].get_octet(), h[3].get_octet(),
			h[4].get_octet(), h[5].get_octet(), h[6].get_octet(), h[7].get_octet());

	DEBUGC_STREAM_RETURNS_OK;
	return ret;
}


bool
ItsPkiSession::EcEnrollmentRequest_InnerEcRequest(ItsPkiInternalData &idata, EtsiTs102941TypesEnrolment::InnerEcRequest &inner_ec_request)
{
	DEBUGC_STREAM_CALLED;

	std::string id_str = sessionGetCanonicalId(idata);
	if (id_str.empty())   {
		ERROR_STREAMC << "failed: ITS Canonical ID is not set" << std::endl;
		return false;
	}

	if (!idata.EcCheckAidSsp())   {
		ERROR_STREAMC << "invalid EC permissions" << std::endl;
		return false;
	}

	// IEEE1609dot2BaseTypes::SequenceOfPsidSsp ssp_seq = idata.EcGetAppPermsSsp();
	// requestedSubjectAttributes := { id := omit, validityPeriod := omit, region := omit, assuranceLevel := omit,
	// 	appPermissions := { { psid := 0, ssp := { bitmapSsp := ''O } } },
	// 	certIssuePermissions := omit }
	EtsiTs102941BaseTypes::CertificateSubjectAttributes cert_attrs;
	cert_attrs.id() = OMIT_VALUE;
	cert_attrs.validityPeriod() = OMIT_VALUE;
	cert_attrs.region() = OMIT_VALUE;
	cert_attrs.assuranceLevel() = OMIT_VALUE;
	cert_attrs.appPermissions() = idata.EcGetAppPermsSsp();
	cert_attrs.certIssuePermissions() = OMIT_VALUE;

	// verificationKey := { ecdsaNistP256 := { uncompressedP256 := { x := ''O, y := ''O } } },
	IEEE1609dot2BaseTypes::PublicVerificationKey verif_pubkey;
	if (!GetPublicVerificationKey(sessionGetItsEcVerificationKey(), verif_pubkey))   {
		ERROR_STREAMC << "cannot get Ec PublicVerificationKey: " << std::endl;
		return false;
	}

	EtsiTs102941BaseTypes::PublicKeys pubkeys = EtsiTs102941BaseTypes::PublicKeys(verif_pubkey, OMIT_VALUE);

	// encryptionKey := { supportedSymmAlg := aes128Ccm (0), publicKey := { eciesNistP256 := { uncompressedP256 := { x := ''O, y := ''O } } } }
	if (sessionGetItsEcEncryptionKey() != NULL)   {
		IEEE1609dot2BaseTypes::PublicEncryptionKey encryption_pubkey;
		if (!GetPublicEncryptionKey(sessionGetItsEcEncryptionKey(), encryption_pubkey))   {
			ERROR_STREAMC << "cannot get Ec PublicEncryptionKey: " << std::endl;
			return false;
		}

		pubkeys.encryptionKey() = encryption_pubkey;
	}

	CHARSTRING id = CHARSTRING(id_str.c_str());
	//  InnerEcRequest := { itsId := "", certificateFormat := 1, publicKeys := { verificationKey := { ... }, encryptionKey := { ... } }, requestedSubjectAttributes := { ... } }
	inner_ec_request = EtsiTs102941TypesEnrolment::InnerEcRequest( id, ItsPkiInternalData::CertificateFormat::ts103097v131, pubkeys, cert_attrs);
    
	DEBUGC_STREAM_RETURNS_OK;  	
	return true; 
}


bool
ItsPkiSession::EcEnrollmentRequest_HeaderInfo(ItsPkiInternalData &idata, IEEE1609dot2::HeaderInfo &header_info)
{
	DEBUGC_STREAM_CALLED;
	
	// printf("%s +%i: ########## TODO TAI clock ##########\n", __FILE__, __LINE__);
	struct tm tm_tm = {0, 0, 0, 1, 0, 2004 - 1900, 0, 0, 0}, lt = {0};
	time_t t = time(NULL);
    	localtime_r(&t, &lt);

	long long int tm_now = (t - lt.tm_gmtoff - mktime(&tm_tm)) * 1000000l;
	
	INTEGER ii;
	ii.set_long_long_val(tm_now);
	header_info = IEEE1609dot2::HeaderInfo( OMIT_VALUE, OMIT_VALUE, OMIT_VALUE, OMIT_VALUE, OMIT_VALUE,
			OMIT_VALUE, OMIT_VALUE, OMIT_VALUE, OMIT_VALUE );

	header_info.generationTime() = ii;
	header_info.psid() = INTEGER(ITS_APP_NAME_SECURED_CERT_REQUEST);

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiSession::EcEnrollmentRequest_InnerData(ItsPkiInternalData &idata,
		EtsiTs102941TypesEnrolment::InnerEcRequest &inner_request,
		IEEE1609dot2::Ieee1609Dot2Data &inner_data)
{
	DEBUGC_STREAM_CALLED;

	OCTETSTRING inner_ec_request_encoded;
	encInnerEcRequest(inner_request, inner_ec_request_encoded);

	IEEE1609dot2::Ieee1609Dot2Content inner_dot_content;
	inner_dot_content.unsecuredData() = inner_ec_request_encoded;
	inner_dot_content.unsecuredData().set_opaque(&inner_request);

	// data := { protocolVersion := 3, content := { unsecuredData := { ... } } }
	IEEE1609dot2::Ieee1609Dot2Data inner_dot_data = IEEE1609dot2::Ieee1609Dot2Data(Ieee1609Dot2Data_ProtocolVersion, inner_dot_content);
	// payload := { data := { ... }, extDataHash := omit }
	IEEE1609dot2::SignedDataPayload	signed_payload = IEEE1609dot2::SignedDataPayload(inner_dot_data, OMIT_VALUE);

	// headerInfo := { psid := 0, generationTime := 0l,
	// 	expiryTime := omit, generationLocation := omit, p2pcdLearningRequest := omit, missingCrlIdentifier := omit, encryptionKey := omit,
	// 	inlineP2pcdRequest := omit, requestedCertificate := omit } 
	IEEE1609dot2::HeaderInfo header_info;
	if (!EcEnrollmentRequest_HeaderInfo(idata, header_info))   {
		ERROR_STREAMC << "cannot build HeaderInfo" << std::endl;
		return false;
	}

	// tbsData := { payload := { ... }, headerInfo  := { ... } }
	IEEE1609dot2::ToBeSignedData tbs = IEEE1609dot2::ToBeSignedData(signed_payload, header_info);
	OCTETSTRING tbs_encoded;
	if (!encToBeSignedData(tbs, tbs_encoded))  {
		ERROR_STREAMC << "cannot encode ToBeSigned" << std::endl;
		return false;
	}

	IEEE1609dot2BaseTypes::HashAlgorithm hash_algo = idata.GetHashAlgorithm();
	IEEE1609dot2::SignerIdentifier signer_id;
	signer_id.self__() = ASN_NULL(ASN_NULL_VALUE);

	// signature_ := { ecdsaNistP256Signature := { rSig := { x_only := ''O }, sSig := ''O } }
	IEEE1609dot2BaseTypes::Signature signature;
	if (!GetIEEE1609dot2Signature(idata, tbs_encoded, sessionGetItsEcCert(), sessionGetItsEcVerificationKey(), signature))   {
		ERROR_STREAMC << "signing failed" << std::endl;
		return false;
	}

	// signedData := { hashId := sha256 (0), tbsData := { ... }, signer := { self := NULL }, signature_ := { ... } }
	IEEE1609dot2::SignedData inner_sdata;
	inner_sdata.hashId() = hash_algo;
	inner_sdata.tbsData() = tbs;
	inner_sdata.signer() = signer_id;
	inner_sdata.signature__() = signature;

	// content := { signedData := { ... } }
	IEEE1609dot2::Ieee1609Dot2Content inner_content;
	inner_content.signedData() = inner_sdata;

	// enrolmentRequest := { protocolVersion := 3, content := { signedData := { ...  } } }
	inner_data = IEEE1609dot2::Ieee1609Dot2Data(Ieee1609Dot2Data_ProtocolVersion, inner_content);

	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::EncryptSignedData_ForEa(ItsPkiInternalData &idata, OCTETSTRING &tbe, IEEE1609dot2::Ieee1609Dot2Data &ret_encrypted)
{
	DEBUGC_STREAM_CALLED;

	OCTETSTRING cert_blob = idata.GetEACertBlob();
	if (cert_blob.lengthof() == 0)   {
		ERROR_STREAMC << "invalid EA recipient's certificate blob" << std::endl;
		return false;
	}

	IEEE1609dot2::CertificateBase cert = decEtsiTs103097Certificate(cert_blob);
	dump_ttcn_object(cert, "recipient certificate: ");
        if (!cert.toBeSigned().encryptionKey().is_present())   {
		ERROR_STREAMC << "no encryption key in recipient's certificate" << std::endl;
		return false;
	}

	if (!etsiServices.setup_encryptFor(cert))   {
                ERROR_STREAMC << "cannot setup EncryptFor context" << std::endl;
		return false;
	}

	// data-encrypted := { protocolVersion := 3, content := { encryptedData := {
	// 	recipients := { { certRecipInfo := { recipientId := ''O, encKey := { eciesNistP256 := { v := { compressed_y_0 := ''O }, c := ''O, t := ''O } } } } },
	// 	ciphertext := { aes128ccm := { nonce := ''O, ccmCiphertext := ''O } }
	// } } }
	EtsiTs103097Module::EtsiTs103097Data__Encrypted__My my_encrypted;
	if (!etsiServices.EncryptPayload(cert, tbe, my_encrypted))   {
                ERROR_STREAMC << "failed to encrypt payload" << std::endl;
		return false;
	}
	dump_ttcn_object(my_encrypted, "My Encrypted': ");

	ret_encrypted = my_encrypted;

	dump_ttcn_object(ret_encrypted, "returns data 'encrypted for': ");

	if (!ret_encrypted.is_bound())   {
                ERROR_STREAMC << "cannot encode encrypted payload" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiSession::EncryptSignedData_ForEa(ItsPkiInternalData &idata, OCTETSTRING &tbe, OCTETSTRING &ret_encrypted)
{
	DEBUGC_STREAM_CALLED;

	IEEE1609dot2::Ieee1609Dot2Data data_encrypted;
	if (!EncryptSignedData_ForEa(idata, tbe, data_encrypted))   {
		ERROR_STREAMC << "failed to encrypt signed data for EA" << std::endl;
		return false;
	}

	if (!encIeee1609Dot2Data(data_encrypted, ret_encrypted))   {
		ERROR_STREAMC << "failed to encode IEEE1609dot2::Ieee1609Dot2Data for EA" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;	
}


bool
ItsPkiSession::EncryptSignedData_ForAa(ItsPkiInternalData &idata, OCTETSTRING &tbe, OCTETSTRING &ret_encrypted)
{
	return false;
}


bool
ItsPkiSession::EncryptSignedData_ForAa(ItsPkiInternalData &idata, OCTETSTRING &tbe, IEEE1609dot2::Ieee1609Dot2Data &ret_encrypted)
{
	DEBUGC_STREAM_CALLED;

	OCTETSTRING cert_blob = idata.GetAACertBlob();
	IEEE1609dot2::CertificateBase cert = decEtsiTs103097Certificate(cert_blob);
	dump_ttcn_object(cert, "recipient certificate: ");
        if (!cert.toBeSigned().encryptionKey().is_present())   {
		ERROR_STREAMC << "not encryption key in recipient's certificate" << std::endl;
		return false;
	}

	if (!etsiServices.setup_encryptFor(cert))   {
                ERROR_STREAMC << "cannot setup EncryptFor AA context" << std::endl;
		return false;
	}

	EtsiTs103097Module::EtsiTs103097Data__Encrypted__My my_encrypted;
	if (!etsiServices.EncryptPayload(cert, tbe, my_encrypted))   {
                ERROR_STREAMC << "failed to encrypt payload for AA" << std::endl;
		return false;
	}

	if (!my_encrypted.is_bound())   {
                ERROR_STREAMC << "failed to encrypt payload for AA" << std::endl;
		return false;
	}

	ret_encrypted = my_encrypted;
	dump_ttcn_object(ret_encrypted, "returns data 'encrypted for': ");

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiSession::EcEnrollmentResponse_Parse(OCTETSTRING &response_raw, OCTETSTRING &ret_cert)
{
	if (!EcEnrollmentResponse_Parse(response_raw))
		return false;
	
	ret_cert = sessionItsEcCert;
	return true;
}


bool
ItsPkiSession::EcEnrollmentResponse_Parse(OCTETSTRING &response_raw)
{
	DEBUGC_STREAM_CALLED;

	OCTETSTRING payload;
	if (!etsiServices.DecryptPayload(response_raw, payload))   {
                ERROR_STREAMC << "decrypt payload failed" << std::endl;
                return false;
	}
	
	EtsiTs103097Module::EtsiTs103097Data__Signed__My response_data_signed = decEtsiTs103097DataSigned(payload);
	dump_ttcn_object(response_data_signed, "EtsiTs103097Module::EtsiTs103097DataSigned response: ");

	IEEE1609dot2::Ieee1609Dot2Data payload_data = response_data_signed.content().signedData().tbsData().payload().data();
	if (!payload_data.is_present())   {
        	ERROR_STREAMC << "invalid signed payload data" << std::endl;
		return false;
	}
	else if (!payload_data.content().ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_unsecuredData))  {
        	ERROR_STREAMC << "invalid choice" << std::endl;
		return false;
	}

	OCTETSTRING inner_unsecured_data = payload_data.content().unsecuredData();
	EtsiTs102941MessagesCa::EtsiTs102941Data response_inner_data = decEtsiTs102941Data(inner_unsecured_data);
	dump_ttcn_object(response_inner_data, "Response data: ");
	if (!response_inner_data.content().ischosen(EtsiTs102941MessagesCa::EtsiTs102941DataContent::ALT_enrolmentResponse))  {
        	ERROR_STREAMC << "invalid choice" << std::endl;
		return false;
	}
	else if (response_inner_data.content().enrolmentResponse().responseCode() != EtsiTs102941TypesEnrolment::EnrolmentResponseCode::ok)   {
        	ERROR_STREAMC << "enrollment failed with status code '" << response_inner_data.content().enrolmentResponse().responseCode() << "'" << std::endl;
		return false;
	}

	EtsiTs103097Module::EtsiTs103097Certificate cert = response_inner_data.content().enrolmentResponse().certificate();
	dump_ttcn_object(cert, "ITS EC Certificate: ");
	
	if (!encEtsiTs103097Certificate(cert, sessionItsEcCert))    {
        	ERROR_STREAMC << "cannot encode EtsiTs103097Certificate" << std::endl;
		return false;
	}

	if (!getEtsiTs103097CertId(sessionItsEcCert, sessionItsEcId))   {
        	ERROR_STREAMC << "cannot set EtsiTs103097Certificate ID" << std::endl;
		return false;
	}

	dump_ttcn_object(sessionItsEcCert, "ITS EC Certificate (encoded): ");
	
	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::EcEnrollmentResponse_Status(OCTETSTRING &response_raw)
{
	DEBUGC_STREAM_CALLED;

	OCTETSTRING payload;
	if (!etsiServices.DecryptPayload(response_raw, payload))   {
        	ERROR_STREAMC << "cannot decrypt payload" << std::endl;
		return false;
	}
	
	EtsiTs103097Module::EtsiTs103097Data__Signed__My response_data_signed = decEtsiTs103097DataSigned(payload);

	IEEE1609dot2::Ieee1609Dot2Data payload_data = response_data_signed.content().signedData().tbsData().payload().data();
	if (!payload_data.is_present())  {
        	ERROR_STREAMC << "no 'PAYLOAD' in SignedData" << std::endl;
		return false;
	}
	if (!payload_data.content().ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_unsecuredData))   {
        	ERROR_STREAMC << "expected 'UnsecuredData' Ieee1609Dot2Content content type" << std::endl;
		return false;
	}

	EtsiTs102941MessagesCa::EtsiTs102941Data response_inner_data = decEtsiTs102941Data(payload_data.content().unsecuredData());
	if (!response_inner_data.content().ischosen(EtsiTs102941MessagesCa::EtsiTs102941DataContent::ALT_enrolmentResponse))   {
        	ERROR_STREAMC << "expected 'EnrollmentResponse' inner data type " << std::endl;
		return false;
	}

	EtsiTs102941TypesEnrolment::EnrolmentResponseCode respCode = response_inner_data.content().enrolmentResponse().responseCode();
	if (respCode != EtsiTs102941TypesEnrolment::EnrolmentResponseCode::ok)   {
        	ERROR_STREAMC << "expected response code 'OK', received '" << respCode.enum_to_str(respCode) << "'" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


void *
ItsPkiSession::sessionGetTechnicalKey()
{
	if (idata == NULL)
		return NULL;

	if (idata->GetItsTechnicalKey() != NULL)
		return idata->GetItsTechnicalKey();

	return sessionTechnicalKey;
}


void *
ItsPkiSession::sessionGetItsEcVerificationKey()
{
	if (idata == NULL)
		return NULL;

	if (idata->GetItsEcVerificationKey() != NULL)
		return idata->GetItsEcVerificationKey();

	return sessionItsEcVerificationKey;
}


void *
ItsPkiSession::sessionGetItsEcEncryptionKey()
{
	if (idata == NULL)
		return NULL;

	if (idata->GetItsEcEncryptionKey() != NULL)
		return idata->GetItsEcEncryptionKey();

	return sessionItsEcEncryptionKey;
}


void *
ItsPkiSession::sessionGetItsAtVerificationKey()
{
	if (idata == NULL)
		return NULL;

	if (idata->GetItsAtVerificationKey() != NULL)
		return idata->GetItsAtVerificationKey();

	return sessionItsAtVerificationKey;
}


void *
ItsPkiSession::sessionGetItsAtEncryptionKey()
{
	if (idata == NULL)
		return NULL;

	if (idata->GetItsAtEncryptionKey() != NULL)
		return idata->GetItsAtEncryptionKey();
	return sessionItsAtEncryptionKey;
}


bool
ItsPkiSession::sessionCheckEcEnrollmentArguments(ItsPkiInternalData &idata)
{
	DEBUGC_STREAM_CALLED;

	if (sessionGetTechnicalKey() == NULL)   {
		ERROR_STREAMC << "ItsPkiSession::sessionCheckEcEnrollmentArguments() no ITS Technical Key" << std::endl;
		return false;
	}

	if (!idata.CheckEcEnrollmentArguments())   {
		ERROR_STREAMC << "ItsPkiSession::sessionCheckEcEnrollmentArguments() invalid internal EC enrollment request data" << std::endl;
		return false;
	}

	if ((sessionItsEcVerificationKey == NULL) && (idata.GetItsEcVerificationKey() == NULL))   {
		sessionItsEcVerificationKey = ECKey_GeneratePrivateKey(); 
		if (sessionItsEcVerificationKey == NULL)   {
			ERROR_STREAMC << "ItsPkiSession::sessionCheckEcEnrollmentArguments() cannot generaete EC Verification key" << std::endl;
			return false;
		}
	}

	if ((sessionItsEcEncryptionKey == NULL) && (idata.GetItsEcEncryptionKey() == NULL) && idata.IsItsEcEncryptionKeyEnabled())   {
		sessionItsEcEncryptionKey = ECKey_GeneratePrivateKey();
       		if (sessionItsEcEncryptionKey == NULL)   {	
			ERROR_STREAMC << "ItsPkiSession::sessionCheckEcEnrollmentArguments() cannot generaete EC Encryption key" << std::endl;
			return false;
		}
	}

	if (sessionGetCanonicalId(idata).empty())   {
		ERROR_STREAMC << "ItsPkiSession::sessionCheckEcEnrollmentArguments() cannot get session ITS Canonical ID" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::EcEnrollmentRequest_Create(ItsPkiInternalData &idata, OCTETSTRING &request_encoded)
{
	DEBUGC_STREAM_CALLED;

	if (!sessionCheckEcEnrollmentArguments(idata))   {
		ERROR_STREAMC << "ItsPkiSession::EcEnrollmentRequest_Create() invalid Ec session data" << std::endl;
		return false;
	}

	// InnerEcRequest
	EtsiTs102941TypesEnrolment::InnerEcRequest inner_ec_request;
	EcEnrollmentRequest_InnerEcRequest(idata, inner_ec_request);

	// EtsiTS102941Data
	IEEE1609dot2::Ieee1609Dot2Data inner_data;
	if (!EcEnrollmentRequest_InnerData(idata, inner_ec_request, inner_data))   {
		ERROR_STREAMC << "cannot compose InnerData " << std::endl;
		return false;
	}

	EtsiTs102941MessagesCa::EtsiTs102941DataContent etsits_102941_data_content;
	etsits_102941_data_content.enrolmentRequest() = inner_data;

	EtsiTs102941MessagesCa::EtsiTs102941Data etsits_102941_data = EtsiTs102941MessagesCa::EtsiTs102941Data(EtsiTs102941Data_Version, etsits_102941_data_content);

	OCTETSTRING encoded_etsits_102941_data;
	if (!encEtsiTs102941Data(etsits_102941_data, encoded_etsits_102941_data))   {
		ERROR_STREAMC << "cannot encode EtsiTs102941MessagesCa::EtsiTs102941Data" << std::endl;
		return false;
	}

	dump_ttcn_object(etsits_102941_data, "EtsiTs102941Data : ");
	dump_ttcn_object(encoded_etsits_102941_data, "EtsiTs102941Data (encoded): ");

	IEEE1609dot2::Ieee1609Dot2Content content_for_payload;
	content_for_payload.unsecuredData() = encoded_etsits_102941_data;
	content_for_payload.unsecuredData().set_opaque(&etsits_102941_data);

	IEEE1609dot2::Ieee1609Dot2Data env_for_payload = IEEE1609dot2::Ieee1609Dot2Data(Ieee1609Dot2Data_ProtocolVersion, content_for_payload);

	IEEE1609dot2::SignedDataPayload	signed_payload = IEEE1609dot2::SignedDataPayload(env_for_payload,  OMIT_VALUE);

	IEEE1609dot2::HeaderInfo header_info;
	if (!EcEnrollmentRequest_HeaderInfo(idata, header_info))   {
		ERROR_STREAMC << "cannot compose HeaderInfo" << std::endl;
		return false;
	}

	IEEE1609dot2::ToBeSignedData tbs = IEEE1609dot2::ToBeSignedData(signed_payload, header_info);
	OCTETSTRING tbs_encoded;
	if (!encToBeSignedData(tbs, tbs_encoded))   {
		ERROR_STREAMC << "cannot encode ToBeSignedData" << std::endl;
		return false;
	}

	dump_ttcn_object(tbs, "ToBeSignedData: ");
	dump_ttcn_object(tbs_encoded, "ToBeSignedData (encoded): ");

	IEEE1609dot2BaseTypes::HashAlgorithm hash_algo = idata.GetHashAlgorithm();
	IEEE1609dot2::SignerIdentifier signer_id;
	signer_id.self__() = ASN_NULL(ASN_NULL_VALUE);

	IEEE1609dot2BaseTypes::Signature signature;
	OCTETSTRING signer = OCTETSTRING(0, NULL);
	if (!GetIEEE1609dot2Signature(idata, tbs_encoded, signer, sessionGetTechnicalKey(), signature))   {
		ERROR_STREAMC << "failed to sign" << std::endl;
		return false;
	}

	// EtsiTs103097Data-Signed  (outer)
	IEEE1609dot2::SignedData outer_sdata;
	outer_sdata.hashId() = hash_algo;
	outer_sdata.tbsData() = tbs;
	outer_sdata.signer() = signer_id;
	outer_sdata.signature__() = signature;

	IEEE1609dot2::Ieee1609Dot2Content outer_content;
	outer_content.signedData() = outer_sdata;

	// EtsiTs103097Data-data  (outer)
	IEEE1609dot2::Ieee1609Dot2Data outer_data = IEEE1609dot2::Ieee1609Dot2Data(Ieee1609Dot2Data_ProtocolVersion, outer_content);
        OCTETSTRING outer_data_encoded;
	encIeee1609Dot2Data(outer_data, outer_data_encoded);
	
	dump_ttcn_object(outer_data, "IEEE1609dot2::Ieee1609Dot2Data : ");
	dump_ttcn_object(outer_data_encoded, "IEEE1609dot2::Ieee1609Dot2Data (encoded): ");

	if (!EncryptSignedData_ForEa(idata, outer_data_encoded, request_encoded))   {
		ERROR_STREAMC << "cannot encrypt signed data for EA" << std::endl;
		return false;
	}
	dump_ttcn_object(request_encoded, "Encrypted and encoded EC request: ");

	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::EcEnrollmentResponse_SaveToFiles(ItsPkiInternalData &idata, OCTETSTRING &cert_encoded)
{
	DEBUGC_STREAM_CALLED;
	
	std::string save2file = idata.GetItsEcCertSave2File();
	if (!save2file.empty())   {
		if (writeToFile(save2file.c_str(), (const unsigned char *)cert_encoded, cert_encoded.lengthof()))   {
        		ERROR_STREAMC << "cannot write ITS EC certificate to file '" << save2file << "'" << std::endl;
			return false;
		}
	}

	save2file = idata.GetItsEcVerificationKeySave2File();
	if (!save2file.empty())   {
		if (!ECKey_PrivateKeyToFile(sessionGetItsEcVerificationKey(), save2file.c_str()))   {
        		ERROR_STREAMC << "cannot store ITS EC verification key to file '" << save2file << "'" << std::endl;
			return false;
		}
	}

	save2file = idata.GetItsEcEncryptionKeySave2File();
	if (!save2file.empty())   {
		if (!ECKey_PrivateKeyToFile(sessionGetItsEcEncryptionKey(), save2file.c_str()))   {
        		ERROR_STREAMC << "cannot store ITS EC encryption key to file '" << save2file << "'" << std::endl;
			return false;
		}
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


// At Request
bool
ItsPkiSession::sessionCheckAtEnrollmentArguments(ItsPkiInternalData &idata)
{
	DEBUGC_STREAM_CALLED;

	if (!idata.CheckAtEnrollmentArguments())   {
		ERROR_STREAMC << "ItsPkiSession::sessionCheckAtEnrollmentArguments() invalid internal AT enrollment request data" << std::endl;
		return false;
	}

	if ((sessionItsAtVerificationKey == NULL) && (idata.GetItsAtVerificationKey() == NULL))   {
		sessionItsAtVerificationKey = ECKey_GeneratePrivateKey(); 
		if (sessionItsAtVerificationKey == NULL)   {
			ERROR_STREAMC << "ItsPkiSession::sessionCheckAtEnrollmentArguments() cannot generaete At Verification key" << std::endl;
			return false;
		}
	}

	if ((sessionItsAtEncryptionKey == NULL) && (idata.GetItsAtEncryptionKey() == NULL) && idata.IsItsAtEncryptionKeyEnabled())   {
		sessionItsAtEncryptionKey = ECKey_GeneratePrivateKey();
       		if (sessionItsAtEncryptionKey == NULL)   {	
			ERROR_STREAMC << "ItsPkiSession::sessionCheckAtEnrollmentArguments() cannot generaete At Encryption key" << std::endl;
			return false;
		}
	}

	if (sessionGetCanonicalId(idata).empty())   {
		ERROR_STREAMC << "ItsPkiSession::sessionCheckEcEnrollmentArguments() cannot get session ITS Canonical ID" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::AtEnrollmentRequest_HeaderInfo(ItsPkiInternalData &idata, IEEE1609dot2::HeaderInfo &header_info)
{
	DEBUGC_STREAM_CALLED;
	if (!EcEnrollmentRequest_HeaderInfo(idata, header_info))   {
        	ERROR_STREAMC << "cannot compose AT HeaderInfo " << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::AtEnrollmentRequest_SignedExternalPayload(ItsPkiInternalData &idata,
		EtsiTs102941TypesAuthorization::SharedAtRequest &sharedAtRequest,
		EtsiTs103097Module::EtsiTs103097Data__SignedExternalPayload &ret)
{
	DEBUGC_STREAM_CALLED;

	IEEE1609dot2::HeaderInfo header_info;
	if (!AtEnrollmentRequest_HeaderInfo(idata, header_info))   {
        	ERROR_STREAMC << "failed to compose AT HeaderInfo " << std::endl;
		return false;
	}

	OCTETSTRING sharedAtRequest_encoded;
	if (!encSharedAtRequest(sharedAtRequest, sharedAtRequest_encoded))   {
		ERROR_STREAMC << "cannot encode EtsiTs102941TypesAuthorization::SharedAtRequest" << std::endl;
		return false;
	}
	dump_ttcn_object(sharedAtRequest_encoded, "SharedAtRequest encoded: ");

	OCTETSTRING sharedAtRequest_hash;
	if (!hash_256(sharedAtRequest_encoded, sharedAtRequest_hash))   {
		ERROR_STREAMC << "cannot get hash of sharedAtRequest" << std::endl;
		return false;
	}
	dump_ttcn_object(sharedAtRequest_hash, "SharedAtRequest encoded hash: ");

	IEEE1609dot2::HashedData sharedAtRequest_hashedData;
	sharedAtRequest_hashedData.sha256HashedData() = sharedAtRequest_hash;
	dump_ttcn_object(sharedAtRequest_hashedData, "SharedAtRequest hashedData: ");

	IEEE1609dot2::SignedDataPayload	signed_payload = IEEE1609dot2::SignedDataPayload(OMIT_VALUE, sharedAtRequest_hashedData);

	IEEE1609dot2::ToBeSignedData tbs = IEEE1609dot2::ToBeSignedData(signed_payload, header_info);
	OCTETSTRING tbs_encoded;
	if (!encToBeSignedData(tbs, tbs_encoded))   {
		ERROR_STREAMC << "failed to encode ToBeSignedData" << std::endl;
		return false;
	}
	dump_ttcn_object(tbs_encoded, "ToBeSigned encoded: ");

	IEEE1609dot2::SignerIdentifier signer_id;
	signer_id.digest() = sessionGetItsEcId();

	IEEE1609dot2BaseTypes::Signature signature;
	if (!GetIEEE1609dot2Signature(idata, tbs_encoded, sessionGetItsEcCert(), sessionGetItsEcVerificationKey(), signature))   {
		ERROR_STREAMC << "failed to sign" << std::endl;
		return false;
	}

	IEEE1609dot2::SignedData sep_sdata;
	sep_sdata.hashId() = idata.GetHashAlgorithm();
	sep_sdata.tbsData() = tbs;
	sep_sdata.signer() = signer_id;
	sep_sdata.signature__() = signature;

	IEEE1609dot2::Ieee1609Dot2Content sep_content;
	sep_content.signedData() = sep_sdata;

	ret = EtsiTs103097Module::EtsiTs103097Data__SignedExternalPayload(Ieee1609Dot2Data_ProtocolVersion, sep_content);
	dump_ttcn_object(ret, "EtsiTs103097Data__SignedExternalPayload: ");

	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::AtEnrollmentRequest_POP(ItsPkiInternalData &idata,
		EtsiTs102941MessagesCa::EtsiTs102941Data &etsiTsdata,
		EtsiTs103097Module::EtsiTs103097Data__Signed__My  &ret)
{
	DEBUGC_STREAM_CALLED;

	OCTETSTRING etsiTsdata_encoded;
	if (!encEtsiTs102941Data(etsiTsdata, etsiTsdata_encoded))   {
		ERROR_STREAMC << "cannot encode EtsiTs102941MessagesCa::EtsiTs102941Data" << std::endl;
		return false;
	}

	IEEE1609dot2::Ieee1609Dot2Content dot2_content;
	dot2_content.unsecuredData() = etsiTsdata_encoded;
	dot2_content.unsecuredData().set_opaque(&etsiTsdata);

	IEEE1609dot2::Ieee1609Dot2Data dot2_data = IEEE1609dot2::Ieee1609Dot2Data(Ieee1609Dot2Data_ProtocolVersion, dot2_content);
	IEEE1609dot2::SignedDataPayload	signed_payload = IEEE1609dot2::SignedDataPayload(dot2_data, OMIT_VALUE);

	IEEE1609dot2::HeaderInfo header_info;
	if (!AtEnrollmentRequest_HeaderInfo(idata, header_info))   {
        	ERROR_STREAMC << "cannot compose AT HeaderInfo " << std::endl;
		return false;
	}

	IEEE1609dot2::ToBeSignedData tbs = IEEE1609dot2::ToBeSignedData(signed_payload, header_info);
	OCTETSTRING tbs_encoded;
	if (!encToBeSignedData(tbs, tbs_encoded))   {
		ERROR_STREAMC << "failed to encode ToBeSignedData" << std::endl;
		return false;
	}

	IEEE1609dot2BaseTypes::HashAlgorithm hash_algo = idata.GetHashAlgorithm();

	IEEE1609dot2::SignerIdentifier signer_id;
	signer_id.self__() = ASN_NULL(ASN_NULL_VALUE);

	IEEE1609dot2BaseTypes::Signature signature;
	OCTETSTRING signer = OCTETSTRING(0, NULL);
	if (!GetIEEE1609dot2Signature(idata, tbs_encoded, signer, sessionGetItsAtVerificationKey(), signature))   {
		ERROR_STREAMC << "failed to sign" << std::endl;
		return false;
	}

	IEEE1609dot2::SignedData signedDataContentSignedData;
	signedDataContentSignedData.hashId() = hash_algo;
	signedDataContentSignedData.tbsData() = tbs;
	signedDataContentSignedData.signer() = signer_id;
	signedDataContentSignedData.signature__() = signature;

	IEEE1609dot2::Ieee1609Dot2Content signedDataContent;
	signedDataContent.signedData() = signedDataContentSignedData;
	ret = EtsiTs103097Module::EtsiTs103097Data__Signed__My(Ieee1609Dot2Data_ProtocolVersion, signedDataContent);
	
	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::AtEnrollmentRequest_InnerAtRequest(ItsPkiInternalData &idata, OCTETSTRING &ret)
{
	DEBUGC_STREAM_CALLED;

#if 0
	if (!idata.CheckAtEnrollmentArguments())   {
		ERROR_STREAMC << "ItsPkiSession::AtEnrollmentRequest_InnerAtRequest() invalid internal AT enrollment data" << std::endl;
		return false;
	}
#else
	if (!sessionCheckAtEnrollmentArguments(idata))   {
		ERROR_STREAMC << "ItsPkiSession::AtEnrollmentRequest_Create() invalid At session data" << std::endl;
		return false;
	}
#endif
	IEEE1609dot2BaseTypes::PublicVerificationKey v_pubkey;
        if (!GetItsAtPublicVerificationKey(v_pubkey))   {
		ERROR_STREAMC << "cannot get ITS AT PublicVerificationKey" << std::endl;
		return false;
	}

	OCTETSTRING v_pubkey_encoded;
	if (!encPublicVerificationKey(v_pubkey, v_pubkey_encoded))   {
		ERROR_STREAMC << "cannot encode ITS AT PublicVerificationKey" << std::endl;
		return false;
	}

	IEEE1609dot2BaseTypes::PublicEncryptionKey e_pubkey;
	OCTETSTRING e_pubkey_encoded = OCTETSTRING(0, NULL);
	if(sessionGetItsAtEncryptionKey() != NULL)   {
		if (!GetItsAtPublicEncryptionKey(e_pubkey))   {
			ERROR_STREAMC << "cannot get ITS AT PublicEncryptionKey" << std::endl;
			return false;
		}

		if (!encPublicEncryptionKey(e_pubkey, e_pubkey_encoded))   {
			ERROR_STREAMC << "cannot encode ITS AT PublicEncryptionKey" << std::endl;
			return false;
		}
	}

	OCTETSTRING hmac = random_OCTETSTRING(SHA256_DIGEST_LENGTH);
	dump_ttcn_object(hmac, "HMAC: ");

	// size_t tag_len = EtsiTs102941TypesAuthorization::SharedAtRequest_keyTag_descr_.oer->length;
	OCTETSTRING keyTag;
	OCTETSTRING pub_keys = v_pubkey_encoded + e_pubkey_encoded;
	dump_ttcn_object(pub_keys, "PubKeys encoded: ");
	
	if (!hmac_sha256(pub_keys, hmac, keyTag))   {
		ERROR_STREAMC << "failed to generate HMAC: " << std::endl;
		return false;
	}
	dump_ttcn_object(keyTag, "KeyTag: ");
	
        IEEE1609dot2BaseTypes::SequenceOfPsidSsp ssp_seq = idata.AtGetAppPermsSsp();
        EtsiTs102941BaseTypes::CertificateSubjectAttributes cert_attrs = EtsiTs102941BaseTypes::CertificateSubjectAttributes(
			OMIT_VALUE, OMIT_VALUE, OMIT_VALUE, OMIT_VALUE, ssp_seq, OMIT_VALUE);

	EtsiTs102941TypesAuthorization::SharedAtRequest sharedAtRequest;
	sharedAtRequest.eaId() = idata.GetEAId(); 
	sharedAtRequest.keyTag() = keyTag; 
	sharedAtRequest.certificateFormat() = ItsPkiInternalData::CertificateFormat::ts103097v131; 
	sharedAtRequest.requestedSubjectAttributes() = cert_attrs; 
	dump_ttcn_object(sharedAtRequest, "EtsiTs102941TypesAuthorization::SharedAtRequest: ");

	EtsiTs103097Module::EtsiTs103097Data__SignedExternalPayload signedExternalPayload;
	if (!AtEnrollmentRequest_SignedExternalPayload(idata, sharedAtRequest, signedExternalPayload))   {
                ERROR_STREAMC << "cannot create SignedExternalPayload " << std::endl;
                return false;
	}
	dump_ttcn_object(signedExternalPayload, "SignedExternalPayload : ");
	
	OCTETSTRING signedExternalPayload_encoded;
	if (!encSignedExternalPayload(signedExternalPayload, signedExternalPayload_encoded))   {
                ERROR_STREAMC << "cannot encode SignedExternalPayload " << std::endl;
                return false;
	}

	EtsiTs103097Module::EtsiTs103097Data__Encrypted__My signedExternalPayload_encrypted;
	if (!EncryptSignedData_ForEa(idata, signedExternalPayload_encoded, signedExternalPayload_encrypted))   {
                ERROR_STREAMC << "failed to encrypt signed data for EA" << std::endl;
		return false;
	}
	dump_ttcn_object(signedExternalPayload_encrypted, "signedExternalPayload encrypted: ");

	EtsiTs102941BaseTypes::EcSignature ec_signature;
	ec_signature.encryptedEcSignature() = signedExternalPayload_encrypted;
	dump_ttcn_object(ec_signature, "EcSignature: ");

	// InnerAtRequest { publicKeys, hmacKey, sharedAtRequest, ecSignature, ...  
	EtsiTs102941TypesAuthorization::InnerAtRequest innerAtRequest;
	innerAtRequest.hmacKey() = hmac;
	innerAtRequest.sharedAtRequest() = sharedAtRequest;
	innerAtRequest.ecSignature() = ec_signature;

	innerAtRequest.publicKeys() = EtsiTs102941BaseTypes::PublicKeys(v_pubkey, OMIT_VALUE);
	if(sessionGetItsAtEncryptionKey() != NULL)
		innerAtRequest.publicKeys().encryptionKey() = e_pubkey;
	dump_ttcn_object(innerAtRequest.publicKeys(), "innerAtRequest.publicKeys: ");

	EtsiTs102941MessagesCa::EtsiTs102941DataContent atDataContent;
	atDataContent.authorizationRequest() = innerAtRequest;

	// EtsiTs102941Data { InnerAtRequest ...
	EtsiTs102941MessagesCa::EtsiTs102941Data atData = EtsiTs102941MessagesCa::EtsiTs102941Data(EtsiTs102941Data_Version, atDataContent);
	dump_ttcn_object(atData, "EtsiTs102941Data: ");

	EtsiTs103097Module::EtsiTs103097Data__Signed__My signedData;
	if (!AtEnrollmentRequest_POP(idata, atData, signedData))   {
                ERROR_STREAMC << "POP failed" << std::endl;
		return false;
	}
	dump_ttcn_object(signedData, "EtsiTs103097Data__Signed__My: ");

	OCTETSTRING signedData_encoded;
	encEtsiTs103097Data__Signed__My(signedData, signedData_encoded);

	EtsiTs103097Module::EtsiTs103097Data__Encrypted__My dataEncrypted;
	if (!EncryptSignedData_ForAa(idata, signedData_encoded, dataEncrypted))   {
                ERROR_STREAMC << "cannot encrypt Data-Signed for AA " << std::endl;
                return false;
	}
	dump_ttcn_object(dataEncrypted, "EtsiTs102941Data-Encrypted: ");
	if (!encIeee1609Dot2Data(dataEncrypted, ret))   {
                ERROR_STREAMC << "cannot encode encrypted Data-Signed for AA " << std::endl;
                return false;
	}
	dump_ttcn_object(ret, "EtsiTs102941Data-Encrypted (encoded): ");

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}	


bool
ItsPkiSession::AtEnrollmentResponse_Status(OCTETSTRING &response_raw)
{
	DEBUGC_STREAM_CALLED;

	OCTETSTRING payload;
	if (!etsiServices.DecryptPayload(response_raw, payload))   {
        	ERROR_STREAMC << "cannot decrypt payload" << std::endl;
		return false;
	}
	
	EtsiTs103097Module::EtsiTs103097Data__Signed__My response_data_signed = decEtsiTs103097DataSigned(payload);

	IEEE1609dot2::Ieee1609Dot2Data payload_data = response_data_signed.content().signedData().tbsData().payload().data();
	if (!payload_data.is_present())   {
        	ERROR_STREAMC << "no 'PAYLOAD' in SignedData" << std::endl;
		return false;
	}
	if (!payload_data.content().ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_unsecuredData))   {
        	ERROR_STREAMC << "expected 'UnsecuredData' Ieee1609Dot2Content content type" << std::endl;
		return false;
	}

	EtsiTs102941MessagesCa::EtsiTs102941Data response_inner_data = decEtsiTs102941Data(payload_data.content().unsecuredData());
	if (!response_inner_data.content().ischosen(EtsiTs102941MessagesCa::EtsiTs102941DataContent::ALT_authorizationResponse))   {
        	ERROR_STREAMC << "expected 'AuthorizationResponse' inner data type " << std::endl;
		return false;
	}

	EtsiTs102941TypesAuthorization::AuthorizationResponseCode respCode = response_inner_data.content().authorizationResponse().responseCode();
	if (respCode != EtsiTs102941TypesAuthorization::AuthorizationResponseCode::ok)   {
        	ERROR_STREAMC << "expected response code 'OK', received '" << respCode.enum_to_str(respCode) << "'" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::AtEnrollmentResponse_Parse(OCTETSTRING &response_raw, OCTETSTRING &ret_cert)
{
	DEBUGC_STREAM_CALLED;

	OCTETSTRING payload;
	if (!etsiServices.DecryptPayload(response_raw, payload))   {
                ERROR_STREAMC << "decrypt payload failed" << std::endl;
                return false;
	}
	
	EtsiTs103097Module::EtsiTs103097Data__Signed__My response_data_signed = decEtsiTs103097DataSigned(payload);
	dump_ttcn_object(response_data_signed, "Response EtsiTs103097DataSigned__My: ");

	IEEE1609dot2::Ieee1609Dot2Data payload_data = response_data_signed.content().signedData().tbsData().payload().data();
	if (!payload_data.is_present())   {
        	ERROR_STREAMC << "invalid signed payload data" << std::endl;
		return false;
	}
	else if (!payload_data.content().ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_unsecuredData))  {
        	ERROR_STREAMC << "invalid choice: '" << payload_data.content().get_selection() << "'" << std::endl;
		return false;
	}

	OCTETSTRING inner_unsecured_data = payload_data.content().unsecuredData();
	EtsiTs102941MessagesCa::EtsiTs102941Data response_inner_data = decEtsiTs102941Data(inner_unsecured_data);
	dump_ttcn_object(response_inner_data, "Response Inner EtsiTs102941Data: ");

	if (!response_inner_data.content().ischosen(EtsiTs102941MessagesCa::EtsiTs102941DataContent::ALT_authorizationResponse))  {
        	ERROR_STREAMC << "invalid response inner data type: '" << response_inner_data.content().get_selection() << "'" << std::endl;
		return false;
	}

	EtsiTs102941TypesAuthorization::InnerAtResponse inner_at_response = response_inner_data.content().authorizationResponse();
	dump_ttcn_object(inner_at_response, "EtsiTs102941TypesAuthorization::InnerAtResponse : ");
	if (inner_at_response.responseCode() != EtsiTs102941TypesAuthorization::AuthorizationResponseCode::ok)   {
        	ERROR_STREAMC << "enrollment faild with response status '" << inner_at_response.responseCode() << "'" << std::endl;
		return false;
	}

	EtsiTs103097Module::EtsiTs103097Certificate cert = inner_at_response.certificate();
	dump_ttcn_object(cert, "ITS AT Certificate: ");

	if (!encEtsiTs103097Certificate(cert, ret_cert))    {
        	ERROR_STREAMC << "cannot encode EtsiTs103097Certificate" << std::endl;
		return false;
	}
	dump_ttcn_object(ret_cert, "ITS AT Certificate (encoded): ");

	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::AtEnrollmentResponse_SaveToFiles(ItsPkiInternalData &idata, OCTETSTRING &cert_encoded)
{
	DEBUGC_STREAM_CALLED;

	std::string save2file = idata.GetItsAtCertSave2File();
	if (!save2file.empty())   {
		if (writeToFile(save2file.c_str(), (const unsigned char *)cert_encoded, cert_encoded.lengthof()))   {
        		ERROR_STREAMC << "cannot write ITS AT certificate to file '" << save2file << "'" << std::endl;
			return false;
		}
	}

	save2file = idata.GetItsAtVerificationKeySave2File();
	if (!save2file.empty())   {
		if (!ECKey_PrivateKeyToFile(idata.GetItsAtVerificationKey(), save2file.c_str()))   {
        		ERROR_STREAMC << "cannot store ITS AT verification key to file '" << save2file << "'" << std::endl;
			return false;
		}
	}

	save2file = idata.GetItsAtEncryptionKeySave2File();
	if (!save2file.empty())   {
		if (!ECKey_PrivateKeyToFile(idata.GetItsAtEncryptionKey(), save2file.c_str()))   {
        		ERROR_STREAMC << "cannot store ITS AT encryption key to file '" << save2file << "'" << std::endl;
			return false;
		}
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}

