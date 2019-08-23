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
	if (!IEEE1609dot2_Sign(data, signer, key, rSig, sSig))   {
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
ItsPkiSession::IEEE1609dot2_VerifyToBeEncoded(OCTETSTRING &data, OCTETSTRING &signer, void *key,
                OCTETSTRING &rSig, OCTETSTRING &sSig)
{
        DEBUGC_STREAM_CALLED;

        switch (idata->GetHashAlgorithm())   {
        case IEEE1609dot2BaseTypes::HashAlgorithm::sha256:
		if (!IEEE1609dot2_VerifyWithSha256(key, rSig, sSig, data, signer))  {
                        ERROR_STREAMC << "IEEE1609dot2 SHA256 verify failed" << std::endl;
                        return false;
                }
                break;
        case IEEE1609dot2BaseTypes::HashAlgorithm::sha384:
		if (!IEEE1609dot2_VerifyWithSha384(key, rSig, sSig, data, signer))  {
                        ERROR_STREAMC << "IEEE1609dot2 SHA384 verify failed" << std::endl;
                        return false;
                }
                break;
        default:
                ERROR_STREAMC << "Unsupporteds hash algorithm" << idata->GetHashAlgorithm() << std::endl;
                return false;
        }

        DEBUGC_STREAM_RETURNS_OK;
        return true;
}


bool
ItsPkiSession::IEEE1609dot2_VerifySignedData(IEEE1609dot2::SignedData &signed_data, void *key,
		IEEE1609dot2::SignedDataPayload &ret_payload)
{
        DEBUGC_STREAM_CALLED;

	OCTETSTRING sSig, rSig;
	IEEE1609dot2BaseTypes::Signature signature = signed_data.signature__();
	if (signature.ischosen(IEEE1609dot2BaseTypes::Signature::ALT_ecdsaNistP256Signature))   {
		sSig = signature.ecdsaNistP256Signature().sSig();
		if (signature.ecdsaNistP256Signature().rSig().ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_x__only))   {
			rSig = signature.ecdsaNistP256Signature().rSig().x__only();
		}
		else {
        		ERROR_STREAMC << "not supported EccP256CurvePoint type other then ALT_x__only" << std::endl;
			return false;
		}
	}
	else if (signature.ischosen(IEEE1609dot2BaseTypes::Signature::ALT_ecdsaBrainpoolP256r1Signature))   {
		sSig = signature.ecdsaBrainpoolP256r1Signature().sSig();
		if (signature.ecdsaBrainpoolP256r1Signature().rSig().ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_x__only))   {
			rSig = signature.ecdsaBrainpoolP256r1Signature().rSig().x__only();
		}
		else {
        		ERROR_STREAMC << "not supported EccP256CurvePoint type other then ALT_x__only" << std::endl;
			return false;
		}
	}
	else   {
        	ERROR_STREAMC << "not supported Signature type : " << signature.get_selection() << std::endl;
		return false;
	}

	IEEE1609dot2::ToBeSignedData tbs_data = signed_data.tbsData();
        OCTETSTRING tbs_encoded;
	if (!encToBeSignedData(tbs_data, tbs_encoded))   {
	       	ERROR_STREAMC << "cannot encode ToBeSignedData" << std::endl;
		return false;
	}

	OCTETSTRING signer_encoded;
	if (signed_data.signer().ischosen(IEEE1609dot2::SignerIdentifier::ALT_self__))   {
		signer_encoded = OCTETSTRING(0, NULL);
	}
	else if (signed_data.signer().ischosen(IEEE1609dot2::SignerIdentifier::ALT_digest))  {
		if (idata->GetEAId() == signed_data.signer().digest())   {
			signer_encoded = idata->GetEACertBlob();
		}
		else if (idata->GetAAId() == signed_data.signer().digest())   {
			signer_encoded = idata->GetAACertBlob();
		}
		else if (idata->GetItsEcId() == signed_data.signer().digest())   {
			signer_encoded = idata->GetItsEcCertBlob();
		}
		else   {
	       		ERROR_STREAMC << "Expected to be signed by EA or by AA" << std::endl;
			return false;
		}

		if (!idata->getVerificationKeyFromCertificate(signer_encoded, &key))   {
	       		ERROR_STREAMC << "Cannot get verification key from certificate" << std::endl;
			return false;
		}
	}
	else   {
	       	ERROR_STREAMC << "verify with signer other the 'self' do not implemented" << std::endl;
		return false;
	}

	if (key == NULL)   {
		ERROR_STREAMC << "No key to verify signature" << std::endl;
		return false;
	}

	if (!IEEE1609dot2_VerifyToBeEncoded(tbs_encoded, signer_encoded, key, rSig, sSig))  {
                ERROR_STREAMC << "Cannot verify signature" << std::endl;
                return false;
	}

	ret_payload = tbs_data.payload();
        
	DEBUGC_STREAM_RETURNS_OK;
        return true;
}


bool
ItsPkiSession::IEEE1609dot2_VerifySignedData_C(IEEE1609dot2::SignedData &signed_data, void *key,
		IEEE1609dot2::Ieee1609Dot2Content &ret_content)
{
        DEBUGC_STREAM_CALLED;
	
	IEEE1609dot2::SignedDataPayload payload;
	if (!IEEE1609dot2_VerifySignedData(signed_data, key, payload))   {
                ERROR_STREAMC << "cannot verify signed data" << std::endl;
                return false;
	}

	if (payload.data().is_present())   {
		IEEE1609dot2::Ieee1609Dot2Data data = payload.data();
		if (data.protocolVersion() != Ieee1609Dot2Data_ProtocolVersion)   {
                	ERROR_STREAMC << "Unsupported Ieee1609Dot2Data ProtocolVersion : " << data.protocolVersion() << std::endl;
                	return false;
		}
		ret_content = data.content();
	}
	else   {
                ERROR_STREAMC << "expected SignedData payload" << std::endl;
                return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
        return true;
}


bool
ItsPkiSession::IEEE1609dot2_VerifySignedData_H(IEEE1609dot2::SignedData &signed_data, void *key,
		IEEE1609dot2::HashedData &ret_extDataHash)
{
        DEBUGC_STREAM_CALLED;

	IEEE1609dot2::SignedDataPayload payload;
	if (!IEEE1609dot2_VerifySignedData(signed_data, key, payload))   {
                ERROR_STREAMC << "cannot verify signed data" << std::endl;
                return false;
	}

	if (payload.extDataHash().is_present()) {
		ret_extDataHash = payload.extDataHash();
	}
	else   {
                ERROR_STREAMC << "expected SignedData ExtDataHash" << std::endl;
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
ItsPkiSession::ItsRegisterResponse_Parse(OCTETSTRING &response_raw, OCTETSTRING &ret_its_id)
{
	DEBUGC_STREAM_CALLED;

	// TODO: parse properly...
	OCTETSTRING decoded = str2oct(oct2str(response_raw));
	std::string resp((const char *)((const unsigned char *)decoded), decoded.lengthof());

	if (!json_get_tag_value(resp, "id", its_id))   {
		ERROR_STREAMC << "Invalid ITS registration response: no 'id' tag" << std::endl;
		return false;
	}

	ret_its_id = OCTETSTRING(its_id.length(), (const unsigned char *)its_id.c_str());
	
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

	dump_ttcn_object(tbs_encoded, "To be signed encoded: ");
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
ItsPkiSession::EncryptSignedData_ForEa(ItsPkiInternalData &idata, OCTETSTRING &tbe,
		IEEE1609dot2::Ieee1609Dot2Data &ret_encrypted)
{
	DEBUGC_STREAM_CALLED;

	OCTETSTRING cert_blob = idata.GetEACertBlob();
	if (cert_blob.lengthof() == 0)   {
		ERROR_STREAMC << "invalid EA recipient's certificate blob" << std::endl;
		return false;
	}

	if (!etsiServices.setRecipient(cert_blob, NULL))   {
                ERROR_STREAMC << "cannot setup EncryptFor context" << std::endl;
		return false;
	}

	// data-encrypted := { protocolVersion := 3, content := { encryptedData := {
	// 	recipients := { { certRecipInfo := { recipientId := ''O, encKey := { eciesNistP256 := { v := { compressed_y_0 := ''O }, c := ''O, t := ''O } } } } },
	// 	ciphertext := { aes128ccm := { nonce := ''O, ccmCiphertext := ''O } }
	// } } }
	EtsiTs103097Module::EtsiTs103097Data__Encrypted__My data_encrypted;
	if (!etsiServices.EncryptPayload(tbe, data_encrypted))   {
                ERROR_STREAMC << "failed to encrypt payload" << std::endl;
		return false;
	}
	else if (!data_encrypted.is_bound())   {
                ERROR_STREAMC << "cannot encode encrypted payload" << std::endl;
		return false;
	}
	dump_ttcn_object(data_encrypted, "Data Encrypted': ");

	ret_encrypted = data_encrypted;

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
	
	if (!etsiServices.setRecipient(cert_blob, NULL))   {
                ERROR_STREAMC << "cannot setup EncryptFor AA context" << std::endl;
		return false;
	}

	EtsiTs103097Module::EtsiTs103097Data__Encrypted__My data_encrypted;
	if (!etsiServices.EncryptPayload(tbe, data_encrypted))   {
                ERROR_STREAMC << "failed to encrypt payload for AA" << std::endl;
		return false;
	}
	else if (!data_encrypted.is_bound())   {
                ERROR_STREAMC << "failed to encrypt payload for AA" << std::endl;
		return false;
	}

	ret_encrypted = data_encrypted;
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

/*
 * TODO: initialized sessionItsEcCert and sessionItsEcId have an impacto onto the not first EC enrollment
 */
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

	IEEE1609dot2::Ieee1609Dot2Content content;
	if (!IEEE1609dot2_VerifySignedData_C(response_data_signed.content().signedData(), NULL, content))   {
                ERROR_STREAMC << "Cannot verify Signed Data signature" << std::endl;
                return false;
	}
	else if (!content.ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_unsecuredData))  {
        	ERROR_STREAMC << "expected data type 'Ieee1609Dot2Content::ALT_unsecuredData'" << std::endl;
		return false;
	}
	dump_ttcn_object(content, "Signed data content: ");

	OCTETSTRING inner_unsecured_data = content.unsecuredData();
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
	else if (!getEtsiTs103097CertId(sessionItsEcCert, sessionItsEcId))   {
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
	
	EtsiTs103097Module::EtsiTs103097Data__Signed__My data_signed = decEtsiTs103097DataSigned(payload);
	IEEE1609dot2::Ieee1609Dot2Content content;
	if (!IEEE1609dot2_VerifySignedData_C(data_signed.content().signedData(), NULL, content))   {
                ERROR_STREAMC << "Cannot verify Signed Data signature" << std::endl;
                return false;
	}
	else if (!content.ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_unsecuredData))  {
        	ERROR_STREAMC << "expected data type 'Ieee1609Dot2Content::ALT_unsecuredData'" << std::endl;
		return false;
	}
	dump_ttcn_object(content, "Signed data content: ");
	
	EtsiTs102941MessagesCa::EtsiTs102941Data inner_data = decEtsiTs102941Data(content.unsecuredData());
	if (!inner_data.content().ischosen(EtsiTs102941MessagesCa::EtsiTs102941DataContent::ALT_enrolmentResponse))   {
        	ERROR_STREAMC << "expected 'EnrollmentResponse' inner data type " << std::endl;
		return false;
	}

	EtsiTs102941TypesEnrolment::EnrolmentResponseCode respCode = inner_data.content().enrolmentResponse().responseCode();
	if (respCode != EtsiTs102941TypesEnrolment::EnrolmentResponseCode::ok)   {
        	ERROR_STREAMC << "expected response code 'OK', received '" << respCode.enum_to_str(respCode) << "'" << std::endl;
		return false;
	}
	
	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::EcEnrollmentRequest_Parse(OCTETSTRING &request_raw, void *recipient_prvkey, EtsiTs102941TypesEnrolment::InnerEcRequest &inner_ec_request)
{
	DEBUGC_STREAM_CALLED;

	if (!etsiServices.setDecryptContext(recipient_prvkey, NULL))   {
                ERROR_STREAMC << "Cannot set EC enrollment 'Request Parse' context" << std::endl;
                return false;
	}

	OCTETSTRING payload;
	if (!etsiServices.DecryptPayload(request_raw, payload))   {
                ERROR_STREAMC << "decrypt payload failed" << std::endl;
                return false;
	}
	
	EtsiTs103097Module::EtsiTs103097Data__Signed__My request_data_signed = decEtsiTs103097DataSigned(payload);
	dump_ttcn_object(request_data_signed, "Signed request: ");

	IEEE1609dot2::Ieee1609Dot2Content content;
	if (!IEEE1609dot2_VerifySignedData_C(request_data_signed.content().signedData(), sessionGetTechnicalKey(), content))   {
                ERROR_STREAMC << "Cannot verify Signed Data signature" << std::endl;
                return false;
	}
	else if (!content.ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_unsecuredData))  {
        	ERROR_STREAMC << "expected data type 'Ieee1609Dot2Content::ALT_unsecuredData'" << std::endl;
		return false;
	}

	EtsiTs102941MessagesCa::EtsiTs102941Data inner_data;
	try   {
		EtsiTs102941MessagesCa::EtsiTs102941Data_decoder(content.unsecuredData(), inner_data, "OER");
	}
	catch (const TC_Error& tc_error) {
        	ERROR_STREAMC << "cannot decode Ec Enrollment inner-data" << std::endl;
		return false;
	}

	dump_ttcn_object(inner_data, "Inner request data: ");
	if (!inner_data.content().ischosen(EtsiTs102941MessagesCa::EtsiTs102941DataContent::ALT_enrolmentRequest))  {
        	ERROR_STREAMC << "expected data type 'EtsiTs102941DataContent::ALT_enrolmentRequest'" << std::endl;
		return false;
	}

	IEEE1609dot2::Ieee1609Dot2Data enrolment_request = inner_data.content().enrolmentRequest();
	dump_ttcn_object(enrolment_request, "EC enrolment request: ");
	if (enrolment_request.protocolVersion() != Ieee1609Dot2Data_ProtocolVersion)   {
        	ERROR_STREAMC << "Invalid inner data protocol version: " << enrolment_request.protocolVersion() << std::endl;
		return false;
	}
	if (!enrolment_request.content().ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_signedData))  {
        	ERROR_STREAMC << "Expected type 'Ieee1609Dot2Content::ALT_signedData'" << std::endl;
		return false;
	}
	IEEE1609dot2::SignedData signed_data = enrolment_request.content().signedData();
	dump_ttcn_object(signed_data, "Signed Data: ");
	
	if (!IEEE1609dot2_VerifySignedData_C(signed_data, sessionGetItsEcVerificationKey(), content))   {
                ERROR_STREAMC << "Cannot verify Signed Data signature" << std::endl;
                return false;
	}
	else if (!content.ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_unsecuredData))  {
        	ERROR_STREAMC << "expected data type 'Ieee1609Dot2Content::ALT_unsecuredData'" << std::endl;
		return false;
	}

	try   {
		EtsiTs102941TypesEnrolment::InnerEcRequest_decoder(content.unsecuredData(), inner_ec_request, "OER");
	}
	catch (const TC_Error& tc_error) {
        	ERROR_STREAMC << "cannot decode InnerEcRequest data" << std::endl;
		return false;
	}
	dump_ttcn_object(inner_ec_request, "Inner EC request: ");

	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}


bool
ItsPkiSession::IEEE1609dot2_Sign(OCTETSTRING &data, OCTETSTRING &signer,
                void *key,
                OCTETSTRING &rSig, OCTETSTRING &sSig)
{
        DEBUGC_STREAM_CALLED;

        switch (idata->GetHashAlgorithm())   {
        case IEEE1609dot2BaseTypes::HashAlgorithm::sha256:
                if (!IEEE1609dot2_SignWithSha256(data, signer, key, rSig, sSig))   {
                        ERROR_STREAMC << "IEEE1609dot2 SHA256 signature failed" << std::endl;
                        return false;
                }
                break;
        case IEEE1609dot2BaseTypes::HashAlgorithm::sha384:
                if (!IEEE1609dot2_SignWithSha384(data, signer, key, rSig, sSig))   {
                        ERROR_STREAMC << "IEEE1609dot2 SHA384 signature failed" << std::endl;
                        return false;
                }
                break;
        default:
                ERROR_STREAMC << "Unsupporteds hash algorithm" << idata->GetHashAlgorithm() << std::endl;
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

	if (!sessionCheckAtEnrollmentArguments(idata))   {
		ERROR_STREAMC << "ItsPkiSession::AtEnrollmentRequest_Create() invalid At session data" << std::endl;
		return false;
	}

	OCTETSTRING v_pubkey_encoded;
	IEEE1609dot2BaseTypes::PublicVerificationKey v_pubkey;
        if (!GetItsAtPublicVerificationKey(v_pubkey))   {
		ERROR_STREAMC << "cannot get ITS AT PublicVerificationKey" << std::endl;
		return false;
	}
	else if (!encPublicVerificationKey(v_pubkey, v_pubkey_encoded))   {
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
ItsPkiSession::AtEnrollmentRequest_Parse(OCTETSTRING &request_raw, void *ea_prvkey, void *aa_prvkey)
{
	DEBUGC_STREAM_CALLED;

	if (!etsiServices.setDecryptContext(aa_prvkey, NULL))   {
                ERROR_STREAMC << "Cannot set EC enrollment 'Request Parse' context" << std::endl;
                return false;
	}

	OCTETSTRING payload;
	if (!etsiServices.DecryptPayload(request_raw, payload))   {
                ERROR_STREAMC << "decrypt payload failed" << std::endl;
                return false;
	}
	
	EtsiTs103097Module::EtsiTs103097Data__Signed__My request_data_signed = decEtsiTs103097DataSigned(payload);
	dump_ttcn_object(request_data_signed, "Signed request: ");

	IEEE1609dot2::Ieee1609Dot2Content content;
	if (!IEEE1609dot2_VerifySignedData_C(request_data_signed.content().signedData(), sessionGetItsAtVerificationKey(), content))   {
                ERROR_STREAMC << "Cannot verify Signed Data signature" << std::endl;
                return false;
	}
	else if (!content.ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_unsecuredData))  {
        	ERROR_STREAMC << "expected data type 'Ieee1609Dot2Content::ALT_unsecuredData'" << std::endl;
		return false;
	}

	EtsiTs102941MessagesCa::EtsiTs102941Data etsi_ts_data = decEtsiTs102941Data(content.unsecuredData());
	dump_ttcn_object(etsi_ts_data, "Etsi TS Data: ");

	if (etsi_ts_data.version() != EtsiTs102941Data_Version)  {
        	ERROR_STREAMC << "unsupported EtsiTs102941Data version: " << etsi_ts_data.version() << std::endl;
		return false;
	}
	else if (!etsi_ts_data.content().ischosen(EtsiTs102941MessagesCa::EtsiTs102941DataContent::ALT_authorizationRequest))   {
        	ERROR_STREAMC << "expected 'authorizationRequest' data type" << std::endl;
		return false;
	}

	EtsiTs102941TypesAuthorization::InnerAtRequest inner_at_request = etsi_ts_data.content().authorizationRequest();
	EtsiTs102941BaseTypes::PublicKeys pubkeys = inner_at_request.publicKeys();
	OCTETSTRING hmac_key = inner_at_request.hmacKey();
	EtsiTs102941TypesAuthorization::SharedAtRequest shared_at_request = inner_at_request.sharedAtRequest();
	EtsiTs102941BaseTypes::EcSignature ec_signature = inner_at_request.ecSignature();
	dump_ttcn_object(ec_signature, "EcSignature: ");

        OCTETSTRING pubkeys_encoded;
        if (!encPublicVerificationKey(pubkeys.verificationKey(), pubkeys_encoded))   {
        	ERROR_STREAMC << "cannot encode public verification key" << std::endl;
		return false;
	}
	if (pubkeys.encryptionKey().is_present())    {
        	OCTETSTRING e_pubkey_encoded;
		if (!encPublicEncryptionKey(pubkeys.encryptionKey(), e_pubkey_encoded))   {
        		ERROR_STREAMC << "cannot encode public encryption key" << std::endl;
			return false;
		}
		pubkeys_encoded += e_pubkey_encoded;
	}

        OCTETSTRING key_tag;
        if (!hmac_sha256(pubkeys_encoded, hmac_key, key_tag))   {
                ERROR_STREAMC << "failed to generate HMAC of PublicKeys data" << std::endl;
                return false;
        }
	dump_ttcn_object(key_tag, "PublicKeys tag: ");
	if (shared_at_request.keyTag() != key_tag)   {
                ERROR_STREAMC << "unexpected value of PublicKey HMAC" << std::endl;
                return false;
	} 
        
	OCTETSTRING ec_signature_payload;
	if (ec_signature.ischosen(EtsiTs102941BaseTypes::EcSignature::ALT_encryptedEcSignature))   {
        	EtsiTs103097Module::EtsiTs103097Data__Encrypted__My ec_signature_encrypted = ec_signature.encryptedEcSignature();
		
		if (!etsiServices.setRecipient(idata->GetEACertBlob(), ea_prvkey))   {
                	ERROR_STREAMC << "cannot setup EncryptFor context" << std::endl;
			return false;
		}
		else if (!etsiServices.DecryptPayload(ec_signature_encrypted, ec_signature_payload))   {
                	ERROR_STREAMC << "decrypt payload failed" << std::endl;
                	return false;
		}
	}
	else if (ec_signature.ischosen(EtsiTs102941BaseTypes::EcSignature::ALT_ecSignature))   {
        	ERROR_STREAMC << "'ecSignature' type of EcSignature do not supported" << std::endl;
		return false;
	}
	else   {
        	ERROR_STREAMC << "unsupported EcSignature type" << std::endl;
		return false;
	}
	dump_ttcn_object(ec_signature_payload, "Decrypted payload: ");

        EtsiTs103097Module::EtsiTs103097Data__SignedExternalPayload external_payload;
	try  {
        	EtsiTs103097Module::EtsiTs103097Data__SignedExternalPayload_decoder(ec_signature_payload, external_payload, "OER");
	}
	catch (const TC_Error& tc_error) {
        	ERROR_STREAMC << "cannot decode EtsiTs103097Data SignedExternalPayload data" << std::endl;
		return false;
	}
	dump_ttcn_object(external_payload, "Decoded Exrternal Payload: ");

	if (external_payload.protocolVersion() != Ieee1609Dot2Data_ProtocolVersion)   {
        	ERROR_STREAMC << "unexpected ExternalPayload protocol version: " << external_payload.protocolVersion() << std::endl;
		return false;
	}
	else if (!external_payload.content().ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_signedData))   {
        	ERROR_STREAMC << "unexpected Ieee1609Dot2Content data type of external payload: " << external_payload.content().get_selection() << std::endl;
		return false;
	}

	IEEE1609dot2::HashedData ext_data_hash;
	if (!IEEE1609dot2_VerifySignedData_H(external_payload.content().signedData(), sessionGetItsEcVerificationKey(), ext_data_hash))   {
		ERROR_STREAMC << "Cannot verify external payload signed data " << std::endl;
		return false;
	}

	OCTETSTRING sar_encoded, sar_hash;
	if (!encSharedAtRequest(shared_at_request, sar_encoded))   {
		ERROR_STREAMC << "cannot encode EtsiTs102941TypesAuthorization::SharedAtRequest" << std::endl;
		return false;
	}
	else if (!hash_256(sar_encoded, sar_hash))   {
		ERROR_STREAMC << "cannot get hash of sharedAtRequest" << std::endl;
		return false;
	}
	else if (sar_hash != ext_data_hash.sha256HashedData())   {
		ERROR_STREAMC << "unexpected ExternalDataHashvalue" << std::endl;
		return false;
	}

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
	
	EtsiTs103097Module::EtsiTs103097Data__Signed__My data_signed = decEtsiTs103097DataSigned(payload);

	IEEE1609dot2::Ieee1609Dot2Content content;
	if (!IEEE1609dot2_VerifySignedData_C(data_signed.content().signedData(), NULL, content))   {
                ERROR_STREAMC << "Cannot verify Signed Data signature" << std::endl;
                return false;
	}
	else if (!content.ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_unsecuredData))  {
        	ERROR_STREAMC << "expected data type 'Ieee1609Dot2Content::ALT_unsecuredData'" << std::endl;
		return false;
	}
	dump_ttcn_object(content, "Signed data content: ");

	EtsiTs102941MessagesCa::EtsiTs102941Data inner_data = decEtsiTs102941Data(content.unsecuredData());
	dump_ttcn_object(inner_data, "Response Inner Data: ");

	if (!inner_data.content().ischosen(EtsiTs102941MessagesCa::EtsiTs102941DataContent::ALT_authorizationResponse))   {
        	ERROR_STREAMC << "expected 'AuthorizationResponse' inner data type " << std::endl;
		return false;
	}

	EtsiTs102941TypesAuthorization::AuthorizationResponseCode respCode = inner_data.content().authorizationResponse().responseCode();
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
	
	EtsiTs103097Module::EtsiTs103097Data__Signed__My data_signed = decEtsiTs103097DataSigned(payload);
	dump_ttcn_object(data_signed, "Response EtsiTs103097DataSigned__My: ");
	
	IEEE1609dot2::Ieee1609Dot2Content content;
	if (!IEEE1609dot2_VerifySignedData_C(data_signed.content().signedData(), NULL, content))   {
                ERROR_STREAMC << "Cannot verify Signed Data signature" << std::endl;
                return false;
	}
	else if (!content.ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_unsecuredData))  {
        	ERROR_STREAMC << "expected data type 'Ieee1609Dot2Content::ALT_unsecuredData'" << std::endl;
		return false;
	}
	dump_ttcn_object(content, "Signed data content: ");

	EtsiTs102941MessagesCa::EtsiTs102941Data inner_data = decEtsiTs102941Data(content.unsecuredData());
	dump_ttcn_object(inner_data, "Response Inner Data: ");

	if (!inner_data.content().ischosen(EtsiTs102941MessagesCa::EtsiTs102941DataContent::ALT_authorizationResponse))  {
        	ERROR_STREAMC << "invalid response inner data type: '" << inner_data.content().get_selection() << "'" << std::endl;
		return false;
	}

	EtsiTs102941TypesAuthorization::InnerAtResponse inner_at_response = inner_data.content().authorizationResponse();
	dump_ttcn_object(inner_at_response, "EtsiTs102941TypesAuthorization::InnerAtResponse : ");
	if (inner_at_response.responseCode() != EtsiTs102941TypesAuthorization::AuthorizationResponseCode::ok)   {
        	ERROR_STREAMC << "enrollment failed with response status '" << inner_at_response.responseCode() << "'" << std::endl;
		return false;
	}

	EtsiTs103097Module::EtsiTs103097Certificate cert = inner_at_response.certificate();
	dump_ttcn_object(cert, "ITS AT Certificate: ");

	if (!encEtsiTs103097Certificate(cert, sessionItsAtCert))    {
        	ERROR_STREAMC << "cannot encode AT EtsiTs103097Certificate" << std::endl;
		return false;
	}
	dump_ttcn_object(sessionItsAtCert, "ITS AT Certificate (encoded): ");

	ret_cert = sessionItsAtCert;
	DEBUGC_STREAM_RETURNS_OK;
	return true; 
}

