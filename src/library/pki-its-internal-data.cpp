#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <boost/program_options.hpp>

#include "its/utils.hh"
#include "its/pki-its-debug.hh"
#include "its/pki-its-internal-data.hh"
#include "its/its-asn1-modules.hh"


ItsPkiInternalData::ItsPkiInternalData()
{
	DEBUGC_STREAM_CALLED;
	init();
}
	
 
bool
ItsPkiInternalData::SetCanonicalID(const std::string &id, const std::string &its_name_header)
{
	struct timespec ts;
        struct tm *htm = NULL;

	DEBUGC_STREAM_CALLED;

	if (!id.empty())    {
		its_canonical_id = id;
		
		DEBUGC_STREAM_RETURNS_OK;
		return true;
	}

	if (itsEcCert_blob.is_present())   {
		IEEE1609dot2::CertificateBase cert = decEtsiTs103097Certificate(itsEcCert_blob);
		IEEE1609dot2::CertificateId cert_id = cert.toBeSigned().id();
		if (cert_id.ischosen(IEEE1609dot2::CertificateId::ALT_name))   {
			its_canonical_id = unichar2char(cert_id.name());
			
			DEBUGC_STREAM_RETURNS_OK;
			return true;
		}
	}

	if (technicalKey == NULL)   {
		ERROR_STREAMC << "empty Technical Key" << std::endl;
		return false;
	}

	clock_gettime(CLOCK_REALTIME, &ts);
        htm = localtime( &ts.tv_sec );

	OCTETSTRING h;
    	if (!ECKey_PublicKeyHashedID(technicalKey, h))   {
		ERROR_STREAMC << "cannot get HashedID from EC public key" << std::endl;
		return false;
	}

	its_canonical_id = string_format("%s-%i%02i%02i-%02X%02X%02X%02X%02X%02X%02X%02X",
			its_name_header.empty() ? DEFAULT_ITS_CANONICAL_ID_HEADER : its_name_header.c_str(),
			htm->tm_year + 1900, htm->tm_mon + 1, htm->tm_mday,
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


ItsPkiInternalData::~ItsPkiInternalData()
{
	DEBUGC_STREAM_CALLED;
	
	ECKey_Free(technicalKey);
	ECKey_Free(itsEcVerificationKey);
	ECKey_Free(itsEcEncryptionKey);
	ECKey_Free(itsAtVerificationKey);
	ECKey_Free(itsAtEncryptionKey);
	ECKey_Free(eaVerificationKey);
	ECKey_Free(eaEncryptionKey);
	ECKey_Free(aaVerificationKey);
	ECKey_Free(aaEncryptionKey);
}


bool
ItsPkiInternalData::SetAidSsp(const long app_perms_psid,
		const std::string &app_perms_ssp_opaque, const std::string &app_perms_ssp_bitmap)
{
	DEBUGC_STREAM_CALLED;

	if (app_perms_psid == 0)  {
		ERROR_STREAMC << "missing mandatory 'app-perms-psid' argument" << std::endl;
		return false;
	}

	psid_ssp.psid = app_perms_psid;

	if (!app_perms_ssp_opaque.empty())    {
		if ((app_perms_ssp_opaque.length() % 2) != 0)   {
			ERROR_STREAMC << "invalid 'app-perms-ssp opaque' hex string" << std::endl;
			return false;
		}

		psid_ssp.ssp = str2oct(app_perms_ssp_opaque.c_str());
		if (!psid_ssp.ssp.is_bound())   {
			ERROR_STREAMC << "invalid SSP opaque hex string" << std::endl;
			return false;
		}

		psid_ssp.type = IEEE1609dot2BaseTypes::ServiceSpecificPermissions::ALT_opaque;
	}
	else if (!app_perms_ssp_bitmap.empty())    {
		if ((app_perms_ssp_bitmap.length() % 2) != 0)   {
			ERROR_STREAMC << "invalid 'app-perms-ssp bitmap' hex string" << std::endl;
			return false;
		}

		psid_ssp.ssp = str2oct(app_perms_ssp_bitmap.c_str());
		if (!psid_ssp.ssp.is_bound())   {
			ERROR_STREAMC << "invalid PSID SSP hex string" << std::endl;
			return false;
		}

		psid_ssp.type = IEEE1609dot2BaseTypes::ServiceSpecificPermissions::ALT_bitmapSsp;
	}
	else   {
		ERROR_STREAMC << "invalid or missing SSP data" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::CheckAidSsp()
{
	DEBUGC_STREAM_CALLED;

	if (psid_ssp.psid == 0)
		return false;

	if (psid_ssp.type == IEEE1609dot2BaseTypes::ServiceSpecificPermissions::ALT_opaque)   {
		if (!psid_ssp.ssp.is_bound())
			return false;
	}
	else if (psid_ssp.type == IEEE1609dot2BaseTypes::ServiceSpecificPermissions::ALT_bitmapSsp)   {
		if (!psid_ssp.ssp.is_bound())
			return false;
	}
	else   {
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}

bool
ItsPkiInternalData::GetPublicVerificationKey(void *ec_key, IEEE1609dot2BaseTypes::PublicVerificationKey &pubkey)
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
ItsPkiInternalData::GetItsEcPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &pubkey)
{
	DEBUGC_STREAM_CALLED;
	return GetPublicVerificationKey(itsEcVerificationKey, pubkey);
}

bool
ItsPkiInternalData::GetItsAtPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &pubkey)
{
	DEBUGC_STREAM_CALLED;
	return GetPublicVerificationKey(itsAtVerificationKey, pubkey);
}


bool
ItsPkiInternalData::GetPublicEncryptionKey(void *ec_key, IEEE1609dot2BaseTypes::PublicEncryptionKey &pubkey)
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
ItsPkiInternalData::GetItsEcPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &pubkey)
{
	DEBUGC_STREAM_CALLED;
	return GetPublicEncryptionKey(itsEcEncryptionKey, pubkey);
}


bool
ItsPkiInternalData::GetItsAtPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &pubkey)
{
	DEBUGC_STREAM_CALLED;
	return GetPublicEncryptionKey(itsAtEncryptionKey, pubkey);
}


bool
ItsPkiInternalData::IEEE1609dot2_Sign(OCTETSTRING &data, OCTETSTRING &signer,
		void *key,
		OCTETSTRING &rSig, OCTETSTRING &sSig)
{
	DEBUGC_STREAM_CALLED;

	switch (GetHashAlgorithm())   {
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
		ERROR_STREAMC << "Unsupporteds hash algorithm" << GetHashAlgorithm() << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::getCertId(OCTETSTRING &cert_raw, OCTETSTRING &ret_certId)
{
	DEBUGC_STREAM_CALLED;
	
	IEEE1609dot2::module_object.pre_init_module();
	IEEE1609dot2BaseTypes::module_object.pre_init_module();

	IEEE1609dot2::CertificateBase cert = decEtsiTs103097Certificate(cert_raw);

	IEEE1609dot2::VerificationKeyIndicator vKeyIndicator = cert.toBeSigned().verifyKeyIndicator();
	if (!vKeyIndicator.ischosen(IEEE1609dot2::VerificationKeyIndicator::ALT_verificationKey))   {
		ERROR_STREAMC << "ItsPkiInternalData::SetCertID() not supported type of VerificationKeyIndicator" << std::endl;
		return false;	
	}

	IEEE1609dot2BaseTypes::PublicVerificationKey pubKey = vKeyIndicator.verificationKey();
	if (pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaNistP256) || 
			pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaBrainpoolP256r1))   {
		if (!OpenSSL_SHA256_HashedID(cert_raw, ret_certId))   {
			ERROR_STREAMC << "ItsPkiInternalData::SetCertID() OpenSSL SHA256 HashedID failed" << std::endl;
			return false;
		}
	}
	else if (pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaBrainpoolP384r1))   {
		if (!OpenSSL_SHA384_HashedID(cert_raw, ret_certId))   {
			ERROR_STREAMC << "ItsPkiInternalData::SetCertID() OpenSSL SHA384 HashedID failed" << std::endl;
			return false;
		}
	}
	else   {
		ERROR_STREAMC << "ItsPkiInternalData::setEncryptionKey() not supported PublicVerificationKey type" << std::endl;
		return false;	
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::setEncryptionKey(OCTETSTRING &cert_raw, void **ret_key)
{
	DEBUGC_STREAM_CALLED;
	
	IEEE1609dot2::module_object.pre_init_module();
	IEEE1609dot2BaseTypes::module_object.pre_init_module();

	IEEE1609dot2::CertificateBase cert = decEtsiTs103097Certificate(cert_raw);

	IEEE1609dot2BaseTypes::PublicEncryptionKey pubEncKey = cert.toBeSigned().encryptionKey();
	IEEE1609dot2BaseTypes::BasePublicEncryptionKey basePubEncKey = pubEncKey.publicKey();

	int nid;
	IEEE1609dot2BaseTypes::EccP256CurvePoint ecCurvePoint;
	if (basePubEncKey.ischosen(IEEE1609dot2BaseTypes::BasePublicEncryptionKey::ALT_eciesNistP256))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setEncryptionKey() NistP256" << std::endl;
		ecCurvePoint = basePubEncKey.eciesNistP256();
		nid = NID_X9_62_prime256v1;
	}
	else if (basePubEncKey.ischosen(IEEE1609dot2BaseTypes::BasePublicEncryptionKey::ALT_eciesBrainpoolP256r1)) {
		DEBUGC_STREAM << "ItsPkiInternalData::setEncryptionKey() BrainpoolP256r1" << std::endl;
		ecCurvePoint = basePubEncKey.eciesBrainpoolP256r1();
		nid = NID_brainpoolP256r1;
	}
	else   {
		ERROR_STREAMC << "ItsPkiInternalData::setEncryptionKey() invalid EC key type" << std::endl;
		return false;
	}

	OCTETSTRING comp, x, y;
	int y_bit = -1;
	if (ecCurvePoint.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__0))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setEncryptionKey() compressed Y 0" << std::endl;
		comp = ecCurvePoint.compressed__y__0();
		y_bit = 0;
	}
	else if (ecCurvePoint.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__1))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setEncryptionKey() compressed Y 1" << std::endl;
		comp = ecCurvePoint.compressed__y__1();
		y_bit = 1;
	}
	else if (ecCurvePoint.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_uncompressedP256))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setEncryptionKey() uncompressed P256" << std::endl;
		x = ecCurvePoint.uncompressedP256().x();
		y = ecCurvePoint.uncompressedP256().y();
	}
	else   {
		ERROR_STREAMC << "ItsPkiInternalData::setEncryptionKey() uinsupported EccP256CurvePoint choice" << std::endl;
		return false;
	}

	if (!ECKey_PublicKeyFromComponents(nid, x, y, comp, y_bit, ret_key))   {
		ERROR_STREAMC << "ItsPkiInternalData::setEncryptionKey() failed to set EC PublicKey from componets" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::SetEAEncryptionKey(OCTETSTRING &data)
{
	DEBUGC_STREAM_CALLED;

	if (!ItsPkiInternalData::setEncryptionKey(data, &eaEncryptionKey))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setEACertificate() cannot set EA encryption key" << std::endl;
		return false;
	}
	if (!ItsPkiInternalData::getCertId(data, eaId))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setEACertificate() cannot set ID of EA certificate" << std::endl;
		return false;
	}
	dump_ttcn_object(eaId, "EA ID: ");

	eaCert_blob = data;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::SetAAEncryptionKey(OCTETSTRING &data)
{
	DEBUGC_STREAM_CALLED;
	
	if (!ItsPkiInternalData::setEncryptionKey(data, &aaEncryptionKey))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setAACertificate() cannot set AA encryption key" << std::endl;
		return false;
	}
	if (!ItsPkiInternalData::getCertId(data, aaId))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setAACertificate() cannot set ID of AA certificate" << std::endl;
		return false;
	}
	dump_ttcn_object(aaId, "AA ID: ");
	
	aaCert_blob = data;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::SetItsEcId(OCTETSTRING &data)
{
	DEBUGC_STREAM_CALLED;
	
	if (!getCertId(data, itsEcId))   {
		DEBUGC_STREAM << "ItsPkiInternalData::getCertId(() cannot set Its Ec ID" << std::endl;
		return false;
	}

	dump_ttcn_object(itsEcId, "Its Ec ID: ");
	
	itsEcCert_blob = data;
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


void
ItsPkiInternalData::init()
{
	DEBUGC_STREAM_CALLED;
	
	IEEE1609dot2::module_object.pre_init_module();
	IEEE1609dot2BaseTypes::module_object.pre_init_module();
	EtsiTs103097Module::module_object.pre_init_module();

	psid_ssp.psid = 0;
	psid_ssp.type = IEEE1609dot2BaseTypes::ServiceSpecificPermissions::UNBOUND_VALUE;
	psid_ssp.ssp = OCTETSTRING(0, NULL);
	hash_algorithm = IEEE1609dot2BaseTypes::HashAlgorithm::UNBOUND_VALUE;
}


#if 0
bool
ItsPkiInternalData::ParseItsRegisterCmdArguments(ItsPkiCmdArguments &cmd_args)
{
	DEBUGC_STREAM_CALLED;

	technicalKey = ECKey_GeneratePrivateKey();
	if (technicalKey == NULL)   {
		ERROR_STREAMC << "Failed to generate technical key" << std::endl;
		return false;
	}

	if (!CreateCanonicalID(cmd_args))   {
		ERROR_STREAMC << "Cannot create ITS canonical ID " << std::endl;
		return false;
	}
	DEBUGC_STREAM << "Canonical ID '" << its_canonical_id  << "'" << std::endl;

	if (!cmd_args.its_tkey.empty())
		saveTechnicalKeyFile = cmd_args.its_tkey;
	else
		saveTechnicalKeyFile = its_canonical_id + "-technical-key.pem";
	
	if (cmd_args.profile.empty())   {
		ERROR_STREAMC << "Missing mandatory 'profile' argument" << std::endl;
		return false;
	}
	profile = cmd_args.profile;
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}
#endif


bool
ItsPkiInternalData::CheckEnrollmentDataEA()
{
	DEBUGC_STREAM_CALLED;

	if (!eaCert_blob.is_bound() || eaCert_blob.lengthof() == 0)   {
		ERROR_STREAMC << "invalid EA certificate blob" << std::endl;
		return false;
	}
	if (eaEncryptionKey == NULL)   {
		ERROR_STREAMC << "EA encryption key do not set" << std::endl;
		return false;
	}
	if (!eaId.is_bound() || eaId.lengthof() == 0)   {
		ERROR_STREAMC << "EA ID do not set" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}
	

bool
ItsPkiInternalData::CheckEnrollmentDataAA()
{
	DEBUGC_STREAM_CALLED;

	if (!aaCert_blob.is_bound() || aaCert_blob.lengthof() == 0)   {
		ERROR_STREAMC << "invalid AA certificate blob" << std::endl;
		return false;
	}
	if (aaEncryptionKey == NULL)   {
		ERROR_STREAMC << "AA encryption key do not set" << std::endl;
		return false;
	}
	if (!aaId.is_bound() || aaId.lengthof() == 0)   {
		ERROR_STREAMC << "AA ID do not set" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}
	

bool
ItsPkiInternalData::CheckEnrollmentDataItsEc()
{
	DEBUGC_STREAM_CALLED;

	if (!itsEcId.is_bound() || itsEcId.lengthof() == 0)   {
		DEBUGC_STREAM << "missing ITS EC ID" << std::endl;
		return false;
	}

	if (!itsEcCert_blob.is_bound() || itsEcCert_blob.lengthof() == 0)   {
		DEBUGC_STREAM << "missing ITS EC certificatge blob" << std::endl;
		return false;
	}
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::CheckEcEnrollmentArguments()
{
	DEBUGC_STREAM_CALLED;
	
	if (technicalKey == NULL)   {
		ERROR_STREAMC << "EC enroll: Missing or invalid technical key" << std::endl;
		return false;
	}
	if (itsEcEncryptionKeyEnable)   {
		if (itsEcEncryptionKey == NULL)   {
			ERROR_STREAMC << "EC enroll: cannot read from file, base64 string or generate the EC encryption key "<< std::endl;
			return false;
		}
	}
	if (itsEcVerificationKey == NULL)   {
		ERROR_STREAMC << "EC enroll: cannot read from file, base64 string or generate the EC verification key "<< std::endl;
		return false;
	}
	if (!CheckEnrollmentDataEA())   {
		ERROR_STREAMC << "EC enroll: invalid EA parameters" << std::endl;
		return false;
	}
	if (its_canonical_id.empty())   {
		ERROR_STREAMC << "EC enroll: ITS canonical ID do not set" << std::endl;
		return false;
	}
	if (!CheckAidSsp())   {
		ERROR_STREAMC << "EC enroll: invalid ITS AID SSP" << std::endl;
		return false;
	}
	if ((hash_algorithm != IEEE1609dot2BaseTypes::HashAlgorithm::sha256) && (hash_algorithm != IEEE1609dot2BaseTypes::HashAlgorithm::sha384))   {
		ERROR_STREAMC << "EC enroll: invalid hash algorithm" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}

bool
ItsPkiInternalData::CheckAtEnrollmentArguments()
{
	DEBUGC_STREAM_CALLED;
	
	if (itsAtEncryptionKey == NULL)   {
		ERROR_STREAMC << "At enrollment internal data: needs ITS AT encryption key " << std::endl;
		return false;
	}

	if (itsAtVerificationKey == NULL)   {
		ERROR_STREAMC << "At enroll internal data: needs ITS AT verification key" << std::endl;
		return false;
	}
	if (!CheckEnrollmentDataEA())   {
		ERROR_STREAMC << "At enroll: invalid EA parameters" << std::endl;
		return false;
	}
	if (!CheckEnrollmentDataAA())   {
		ERROR_STREAMC << "At enroll: invalid AA parameters" << std::endl;
		return false;
	}
	if (!CheckEnrollmentDataItsEc())   {
		ERROR_STREAMC << "At enroll: invalid ITS EC data" << std::endl;
		return false;
	}
	if (itsEcVerificationKey == NULL)   {
		ERROR_STREAMC << "At enroll: missing ITS EC verification key" << std::endl;
		return false;
	}
	if (its_canonical_id.empty())   {
		ERROR_STREAMC << "At enroll: ITS canonical ID do not set" << std::endl;
		return false;
	}
	if (!CheckAidSsp())   {
		ERROR_STREAMC << "at enroll: invalid ITS AID SSP" << std::endl;
		return false;
	}
	if ((hash_algorithm != IEEE1609dot2BaseTypes::HashAlgorithm::sha256) && (hash_algorithm != IEEE1609dot2BaseTypes::HashAlgorithm::sha384))   {
		ERROR_STREAMC << "At enroll: invalid hash algorithm" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::GetItsRegisterRequest(std::string &request_str)
{
	DEBUGC_STREAM_CALLED;

	if (technicalKey == NULL)   {
		ERROR_STREAMC << "no Technical Key" << std::endl;
		return false;
	}
	else if (its_canonical_id.empty())   {
		ERROR_STREAMC << "no canonical ID" << std::endl;
		return false;
	}
	else if (profile.empty())   {
		ERROR_STREAMC << "no profile" << std::endl;
		return false;
	}

        unsigned char *key_b64 = NULL;
        size_t key_b64_len = 0;

        if (ECKey_PublicKeyToMemory(technicalKey, &key_b64, &key_b64_len))   {
		ERROR_STREAMC << "cannot write public key to memory" << std::endl;
                return false;
        }

        request_str = std::string("{")  
                + "\"canonicalId\":\"" + its_canonical_id + "\","
                + "\"profile\":\"" + profile + "\","
                + "\"technicalPublicKey\":\"" + (char *)key_b64 + "\","
                + "\"status\":\"ACTIVATED\""
                + "}";

	DEBUGC_STREAM << "ITS REGISTER request: " <<  request_str << std::endl;
        free(key_b64);
        key_b64 = NULL;

	DEBUGC_STREAM_RETURNS_OK;
        return true;
}

