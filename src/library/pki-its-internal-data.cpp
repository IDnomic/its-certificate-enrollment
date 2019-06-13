#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <boost/program_options.hpp>

#include "its/utils.hh"
#include "its/pki-its-debug.hh"
#include "its/pki-its-cmd-args.hh"
#include "its/pki-its-internal-data.hh"
#include "its/its-asn1-modules.hh"


ItsPkiInternalData::ItsPkiInternalData(ItsPkiCmdArguments &cmd_args)
{
	DEBUGC_STREAM_CALLED;
	init();
	valid = ParseCmdArguments(cmd_args);
	if (!valid)
		ERROR_STREAMC << "Cannot parse command line arguments" << std::endl;
	DEBUGC_STREAM << "internal data validated" << std::endl;
}
	
 
ItsPkiInternalData::ItsPkiInternalData(type_cmd_operation_t cmd, ItsPkiCmdArguments &cmd_args)
{
	DEBUGC_STREAM_CALLED;
	init();
	if (cmd == CMD_TYPE_EC_CREATE_ENROLL_REQUEST)
		valid = ParseEcEnrollmentCmdArguments(cmd_args);
	else 	
		valid = ParseCmdArguments(cmd_args);
	if (!valid)
		ERROR_STREAMC << "Cannot parse command line arguments" << std::endl;
	DEBUGC_STREAM << "internal data validated" << std::endl;
}
	
 
bool
ItsPkiInternalData::CreateCanonicalID(ItsPkiCmdArguments &cmd_args)
{
	struct timespec ts;
        struct tm *htm = NULL;

	DEBUGC_STREAM_CALLED;

	if (!cmd_args.its_canonical_id.empty())    {
		its_canonical_id = cmd_args.its_canonical_id;
		
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
			cmd_args.its_name_header.empty() ? DEFAULT_ITS_CANONICAL_ID_HEADER : cmd_args.its_name_header.c_str(),
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
ItsPkiInternalData::BuildAidSsp(ItsPkiCmdArguments &cmd_args)
{
	DEBUGC_STREAM_CALLED;

	if (cmd_args.app_perms_psid == 0)  {
		ERROR_STREAMC << "missing mandatory 'app-perms-psid' argument" << std::endl;
		return false;
	}

	psid_ssp.psid = cmd_args.app_perms_psid;

	if (!cmd_args.app_perms_ssp_opaque.empty())    {
		if ((cmd_args.app_perms_ssp_opaque.length() % 2) != 0)   {
			ERROR_STREAMC << "invalid 'app-perms-ssp opaque' hex string" << std::endl;
			return false;
		}

		psid_ssp.ssp = str2oct(cmd_args.app_perms_ssp_opaque.c_str());
		if (!psid_ssp.ssp.is_bound())   {
			ERROR_STREAMC << "invalid SSP opaque hex string" << std::endl;
			return false;
		}

		psid_ssp.type = IEEE1609dot2BaseTypes::ServiceSpecificPermissions::ALT_opaque;
	}
	else if (!cmd_args.app_perms_ssp_bitmap.empty())    {
		if ((cmd_args.app_perms_ssp_bitmap.length() % 2) != 0)   {
			ERROR_STREAMC << "invalid 'app-perms-ssp bitmap' hex string" << std::endl;
			return false;
		}

		psid_ssp.ssp = str2oct(cmd_args.app_perms_ssp_bitmap.c_str());
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
ItsPkiInternalData::setCertId(OCTETSTRING &cert_raw, OCTETSTRING &ret_certId)
{
	DEBUGC_STREAM_CALLED;
	
	IEEE1609dot2::module_object.pre_init_module();
	IEEE1609dot2BaseTypes::module_object.pre_init_module();

	IEEE1609dot2::CertificateBase cert = decEtsiTs103097Certificate(cert_raw);

	IEEE1609dot2::VerificationKeyIndicator vKeyIndicator = cert.toBeSigned().verifyKeyIndicator();
	if (!vKeyIndicator.ischosen(IEEE1609dot2::VerificationKeyIndicator::ALT_verificationKey))   {
		ERROR_STREAMC << "ItsPkiInternalData::setEncryptionKey() not supported type of VerificationKeyIndicator" << std::endl;
		return false;	
	}

	IEEE1609dot2BaseTypes::PublicVerificationKey pubKey = vKeyIndicator.verificationKey();
	if (pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaNistP256) || 
			pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaBrainpoolP256r1))   {
		if (!OpenSSL_SHA256_HashedID(cert_raw, ret_certId))   {
			ERROR_STREAMC << "OpenSSL SHA256 HashedID failed" << std::endl;
			return false;
		}
	}
	else if (pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaBrainpoolP384r1))   {
		if (!OpenSSL_SHA384_HashedID(cert_raw, ret_certId))   {
			ERROR_STREAMC << "OpenSSL SHA384 HashedID failed" << std::endl;
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
ItsPkiInternalData::setEAEncryptionKey(OCTETSTRING &data)
{
	DEBUGC_STREAM_CALLED;

	if (!ItsPkiInternalData::setEncryptionKey(data, &eaEncryptionKey))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setEACertificate() cannot set EA encryption key" << std::endl;
		return false;
	}
	if (!ItsPkiInternalData::setCertId(data, eaId))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setEACertificate() cannot set ID of EA certificate" << std::endl;
		return false;
	}
	dump_ttcn_object(eaId, "EA ID: ");

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::setAAEncryptionKey(OCTETSTRING &data)
{
	DEBUGC_STREAM_CALLED;
	
	if (!ItsPkiInternalData::setEncryptionKey(data, &aaEncryptionKey))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setAACertificate() cannot set AA encryption key" << std::endl;
		return false;
	}
	if (!ItsPkiInternalData::setCertId(data, aaId))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setAACertificate() cannot set ID of AA certificate" << std::endl;
		return false;
	}
	dump_ttcn_object(aaId, "AA ID: ");

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::setItsEcId(OCTETSTRING &data)
{
	DEBUGC_STREAM_CALLED;
	
	if (!setCertId(data, itsEcId))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setCertId(() cannot set Its Ec ID" << std::endl;
		return false;
	}

	dump_ttcn_object(itsEcId, "Its Ec ID: ");
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::readEACertificateFile(std::string &filename)
{
	DEBUGC_STREAM_CALLED;
	
	if (!read_bytes(filename, eaCert_blob))
		return false;

	return setEAEncryptionKey(eaCert_blob);
}


bool
ItsPkiInternalData::readEACertificateB64(std::string &b64_string)
{
	DEBUGC_STREAM_CALLED;
	
	eaCert_blob = decode_base64(b64_string.c_str());
	if (!eaCert_blob.is_bound())
		return false;
	
	return setEAEncryptionKey(eaCert_blob);
}


bool
ItsPkiInternalData::readAACertificateFile(std::string &filename)
{
	DEBUGC_STREAM_CALLED;
	
	if (!read_bytes(filename, aaCert_blob))
		return false;

	return setAAEncryptionKey(aaCert_blob);
}


bool
ItsPkiInternalData::readAACertificateB64(std::string &b64_string)
{
	DEBUGC_STREAM_CALLED;

	aaCert_blob = decode_base64(b64_string.c_str());
	if (!aaCert_blob.is_bound())
		return false;
	
	return setAAEncryptionKey(aaCert_blob);
}


bool
ItsPkiInternalData::readItsEcCertificateFile(std::string &filename)
{
	DEBUGC_STREAM_CALLED;
	
	if (!read_bytes(filename, itsEcCert_blob))
		return false;

	return setItsEcId(itsEcCert_blob);
}


bool
ItsPkiInternalData::readItsEcCertificateB64(std::string &b64_string)
{
	DEBUGC_STREAM_CALLED;
	
	itsEcCert_blob = decode_base64(b64_string.c_str());
	if (!itsEcCert_blob.is_bound())
		return false;

	return setItsEcId(itsEcCert_blob);
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


bool
ItsPkiInternalData::ParseEcEnrollmentCmdArguments(ItsPkiCmdArguments &cmd_args)
{
	DEBUGC_STREAM_CALLED;
	
	if (!cmd_args.its_tkey.empty())
		technicalKey = ECKey_ReadPrivateKey(cmd_args.its_tkey.c_str());	
	else if (!cmd_args.its_tkey_b64.empty())
		technicalKey = ECKey_ReadPrivateKeyB64(cmd_args.its_tkey_b64.c_str());	
	if (technicalKey == NULL)   {
		ERROR_STREAMC << "EC enroll: Missing or invalid technical key" << std::endl;
		return false;
	}

	if (cmd_args.its_ec_ekey_enable)   {
		itsEcEncryptionKeyEnable = true;
		
		if (!cmd_args.its_ec_ekey.empty())
			itsEcEncryptionKey = ECKey_ReadPrivateKey(cmd_args.its_ec_ekey.c_str()); 
		else if (!cmd_args.its_ec_ekey_b64.empty())
			itsEcEncryptionKey = ECKey_ReadPrivateKeyB64(cmd_args.its_ec_ekey_b64.c_str()); 
		else 
			itsEcEncryptionKey = ECKey_GeneratePrivateKey();
		if (itsEcEncryptionKey == NULL)   {
			ERROR_STREAMC << "EC enroll: cannot read from file, base64 string or generate the EC encryption key "<< std::endl;
			return false;
		}
	}

	if (!cmd_args.its_ec_vkey.empty())
		itsEcVerificationKey = ECKey_ReadPrivateKey(cmd_args.its_ec_vkey.c_str()); 
	else if (!cmd_args.its_ec_vkey_b64.empty())
		itsEcVerificationKey = ECKey_ReadPrivateKeyB64(cmd_args.its_ec_vkey_b64.c_str()); 
	else
		itsEcVerificationKey = ECKey_GeneratePrivateKey();
	if (itsEcVerificationKey == NULL)   {
		ERROR_STREAMC << "EC enroll: cannot read from file, base64 string or generate the EC verification key "<< std::endl;
		return false;
	}

	if (!cmd_args.eacertfile.empty())   {
		if (!readEACertificateFile(cmd_args.eacertfile))   {
			ERROR_STREAMC << "EC enroll: cannot get EA certificate from file '" << cmd_args.eacertfile << "'" << std::endl;
			return false;
		}
	}
	else if (!cmd_args.eacert_b64.empty())   {   
		if (!readEACertificateB64(cmd_args.eacert_b64))    {
			ERROR_STREAMC << "EC enroll: cannot get EA certificate from base64 string" << std::endl;
			return false;
		}
	}
	else   {
		ERROR_STREAMC << "EC enroll: EA certificate is mandatory "<< std::endl;
		return false;
	}

	if (!CreateCanonicalID(cmd_args))   {
		ERROR_STREAMC << "EC enroll: annot compose ITS canonical ID" << std::endl;
		return false;
	}
	DEBUGC_STREAM << "EC enroll: ITS Canonical ID: '" << its_canonical_id << "'" << std::endl;

	if (!BuildAidSsp(cmd_args))   {
		ERROR_STREAMC << "EC enroll: cannot build ITS AID SSP list" << std::endl;
		return false;
	}
	DEBUGC_STREAM << "ITS AID SSP(id=" << psid_ssp.psid << ",tag=" << psid_ssp.type << ",ssp=" << oct2str(psid_ssp.ssp) << ")" << std::endl;

	hash_algorithm = cmd_args.GetHashAlgorithm();

	if (cmd_args.its_ec_cert_save2file.empty())
		itsEcCertSave2File = its_canonical_id + "-EC-cert.oer";
	else
		itsEcCertSave2File = cmd_args.its_ec_certfile;
	
	if (cmd_args.its_ec_vkey_save2file.empty())
		itsEcVerificationKeySave2File = its_canonical_id + "-EC-vkey.pem";
	else
		itsEcVerificationKeySave2File = cmd_args.its_ec_vkey_save2file;

	if (cmd_args.its_ec_ekey_enable)   {
		if (cmd_args.its_ec_ekey_save2file.empty())
			itsEcEncryptionKeySave2File = its_canonical_id + "-EC-ekey.pem";
		else
			itsEcEncryptionKeySave2File = cmd_args.its_ec_ekey_save2file;
	}
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::ParseCmdArguments(ItsPkiCmdArguments &cmd_args)
{
	DEBUGC_STREAM_CALLED;
	
	init();

	if (cmd_args.IsCmdItsRegister())   {
		DEBUGC_STREAM << "Register Operation: " << cmd_args.GetOperation() << std::endl;
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
	}
	else if (cmd_args.IsCmdEcEnrollRequest())   {
		if (!ParseEcEnrollmentCmdArguments(cmd_args))   {
			ERROR_STREAMC << "Invalid EC Enrollment Request arguments" << std::endl;
			return false;
		}
	}
	else if (cmd_args.IsCmdAtEnrollRequest())   {
		DEBUGC_STREAM << "At enroll request (" << cmd_args.GetOperation() << ")" << std::endl;

		if (!cmd_args.its_at_ekey.empty())   {
			itsAtEncryptionKey = ECKey_ReadPrivateKey(cmd_args.its_at_ekey.c_str()); 
		}
		else   {
			itsAtEncryptionKey = ECKey_GeneratePrivateKey();
			DEBUGC_STREAM << "Generated ITS AT Encryption key" << std::endl;
		}
		if (itsAtEncryptionKey == NULL)   {
			ERROR_STREAMC << "At enroll: cannot read from file or generate At encryption key "<< std::endl;
			return false;
		}

		if (!cmd_args.its_at_vkey.empty())   {
			itsAtVerificationKey = ECKey_ReadPrivateKey(cmd_args.its_at_vkey.c_str()); 
		}
		else   {
			itsAtVerificationKey = ECKey_GeneratePrivateKey();
		}
		if (itsAtVerificationKey == NULL)   {
			ERROR_STREAMC << "At enroll: cannot read from file or generate At verification key "<< std::endl;
			return false;
		}

		if (!cmd_args.eacertfile.empty())   {
			if (!readEACertificateFile(cmd_args.eacertfile))   {
				ERROR_STREAMC << "At enroll: cannot get EA certificate from file '" << cmd_args.eacertfile << "'" << std::endl;
				return false;
			}
		}
		else if (!cmd_args.eacert_b64.empty())   {
			if (!readEACertificateB64(cmd_args.eacert_b64))  {
				ERROR_STREAMC << "At enroll: cannot get EA certificate from base64 string" << std::endl;
				return false;
			}
		}
		else   {
			ERROR_STREAMC << "At enroll: missing mandatory EA certificate"<< std::endl;
			return false;
		}

		if (!cmd_args.aacertfile.empty())   {
			if (!readAACertificateFile(cmd_args.aacertfile))   {
				ERROR_STREAMC << "At enroll: cannot get AA certificate from file '" << cmd_args.aacertfile << "'" << std::endl;
				return false;
			}
		}
		else if (!cmd_args.aacert_b64.empty())   {
			if (!readAACertificateB64(cmd_args.aacert_b64))   {
				ERROR_STREAMC << "At enroll: cannot get AA certificate from base64 string" << std::endl;
				return false;
			}
		}
		else   {
			ERROR_STREAMC << "At enroll: missing mandatory AA certificate" << std::endl;
			return false;
		}

		if (!cmd_args.its_ec_certfile.empty())   {
			if (!readItsEcCertificateFile(cmd_args.its_ec_certfile))   {
				ERROR_STREAMC << "At enroll: cannot get ITS EC certificate from file '" << cmd_args.its_ec_certfile << "'" << std::endl;
				return false;
			}
		}
		else if (!cmd_args.its_ec_cert_b64.empty())   {
			if (!readItsEcCertificateB64(cmd_args.its_ec_cert_b64))   {
				ERROR_STREAMC << "At enroll: cannot get ITS EC certificate from base64 string" << std::endl;
				return false;
			}
		}
		else   {
			ERROR_STREAMC << "At enroll: missing mandatory ITS EC certificate" << std::endl;
			return false;
		}

		if (!cmd_args.its_ec_vkey.empty())
			itsEcVerificationKey = ECKey_ReadPrivateKey(cmd_args.its_ec_vkey.c_str()); 
		else if (!cmd_args.its_ec_vkey_b64.empty())
			itsEcVerificationKey = ECKey_ReadPrivateKeyB64(cmd_args.its_ec_vkey_b64.c_str()); 
		if (itsEcVerificationKey == NULL)   {
			ERROR_STREAMC << "At enroll: cannot read ITS EC verification key from file or from base64 string" << std::endl;
			return false;
		}
		
		if (!CreateCanonicalID(cmd_args))   {
			ERROR_STREAMC << "At enroll: Canonical ID From EC certificate failed" << std::endl;
			return false;
		}
		DEBUGC_STREAM << "At enroll: ITS canonical ID '" << its_canonical_id  << "'" << std::endl;

		if (!BuildAidSsp(cmd_args))   {
			ERROR_STREAMC << "Cannot build ITS AID SSP list" << std::endl;
			return false;
		}
		DEBUGC_STREAM << "ITS AID SSP(id=" << psid_ssp.psid << ",tag=" << psid_ssp.type << ",ssp=" << oct2str(psid_ssp.ssp) << ")" << std::endl;

		hash_algorithm = cmd_args.GetHashAlgorithm();

		if (cmd_args.its_at_cert_save2file.empty())   {
			if (!its_canonical_id.empty())
				itsAtCertSave2File = its_canonical_id + "-AT-cert.oer";
		}
		else   {
			itsAtCertSave2File = cmd_args.its_at_cert_save2file;
		}
		
		if (cmd_args.its_at_vkey_save2file.empty())   {
			if (!its_canonical_id.empty())
				itsAtVerificationKeySave2File = its_canonical_id + "-AT-vkey.pem";
		}
		else   {
			itsAtVerificationKeySave2File = cmd_args.its_at_vkey_save2file;
		}

		if (cmd_args.its_at_ekey_enable)   {
			itsAtEncryptionKeyEnable = true;
			if (cmd_args.its_at_ekey_save2file.empty())   {
				if (!its_canonical_id.empty())
					itsAtEncryptionKeySave2File = its_canonical_id + "-AT-ekey.pem";
			}
			else    {
				itsAtEncryptionKeySave2File = cmd_args.its_at_ekey_save2file;
			}
		}

		DEBUGC_STREAM << "AA Enrollment request: internal data OK" << std::endl;
	}
	else   {
		ERROR_STREAMC << "not supported operation '" << cmd_args.GetOperation() << "'" << std::endl;
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

