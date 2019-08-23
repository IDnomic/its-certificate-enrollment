#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>

#include "its/utils.hh"
#include "its/itspki-debug.hh"
#include "its/itspki-internal-data.hh"
#include "its/its-asn1-modules.hh"


ItsPkiInternalData::ItsPkiInternalData()
{
	DEBUGC_STREAM_CALLED;
	init();
}


bool
ItsPkiInternalData::SetItsNameHeader(const std::string &nm_header)
{
	DEBUGC_STREAM_CALLED;

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
        struct tm *htm = localtime( &ts.tv_sec );

	its_name_header = nm_header.empty() ? std::string(DEFAULT_ITS_CANONICAL_ID_HEADER) : nm_header;
	its_name_header += string_format("-%i%02i%02i",  htm->tm_year + 1900, htm->tm_mon + 1, htm->tm_mday);
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::SetCanonicalID(const std::string &id, const std::string &nm_header, void *t_key)
{
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

	if (!nm_header.empty())
		SetItsNameHeader(nm_header);

	if (t_key == NULL)
		return true;

	OCTETSTRING h;
    	if (!ECKey_PublicKeyHashedID(t_key, h))   {
		ERROR_STREAMC << "cannot get HashedID from EC public key" << std::endl;
		return false;
	}

	its_canonical_id = string_format("%s-%02X%02X%02X%02X%02X%02X%02X%02X", its_name_header.c_str(),
			h[0].get_octet(), h[1].get_octet(), h[2].get_octet(), h[3].get_octet(),
			h[4].get_octet(), h[5].get_octet(), h[6].get_octet(), h[7].get_octet());

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


ItsPkiInternalData::~ItsPkiInternalData()
{
	ECKey_Free(technicalKey);
	ECKey_Free(itsEcVerificationKey);
	ECKey_Free(itsEcEncryptionKey);
	ECKey_Free(itsAtVerificationKey);
	ECKey_Free(itsAtEncryptionKey);
}


bool
ItsPkiInternalData::AddAidSsp(IEEE1609dot2BaseTypes::SequenceOfPsidSsp &ssp_seq, 
		const long app_perms_psid, const std::string &app_perms_ssp_opaque, const std::string &app_perms_ssp_bitmap)
{
	DEBUGC_STREAM_CALLED;

	if (app_perms_psid == 0)  {
		ERROR_STREAMC << "missing mandatory 'app-perms-psid' argument" << std::endl;
		return false;
	}
	else if (app_perms_ssp_opaque.empty() && app_perms_ssp_bitmap.empty())   {
		ERROR_STREAMC << "'opaque' or 'bitmap' has to be  present" << std::endl;
		return false;
	}

	IEEE1609dot2BaseTypes::ServiceSpecificPermissions ssp;
	if (!app_perms_ssp_opaque.empty())   {
		if ((app_perms_ssp_opaque.length() % 2) != 0)   {
			ERROR_STREAMC << "invalid 'app-perms-ssp opaque' hex string" << std::endl;
			return false;
		}

		ssp.opaque() = str2oct(app_perms_ssp_opaque.c_str());
	}
	else if (!app_perms_ssp_bitmap.empty())    {
		if ((app_perms_ssp_bitmap.length() % 2) != 0)   {
			ERROR_STREAMC << "invalid 'app-perms-ssp bitmap' hex string" << std::endl;
			return false;
		}

		ssp.bitmapSsp() = str2oct(app_perms_ssp_bitmap.c_str());
	}
	if (!ssp.is_bound())   {
		ERROR_STREAMC << "invalid SSP hex string" << std::endl;
		return false;
	}

	IEEE1609dot2BaseTypes::PsidSsp psid_ssp = IEEE1609dot2BaseTypes::PsidSsp(app_perms_psid, ssp);
	int idx = ssp_seq.is_bound() ? ssp_seq.n_elem() : 0;
	ssp_seq[idx] = psid_ssp;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


// AtAddAidSsp(const long _id, const std::string &_opaque, const std::string &_bitmap) { return AddAidSsp(at_ssp_seq, _id, _opaque, _bitmap); };
bool
ItsPkiInternalData::AddAidSsp(IEEE1609dot2BaseTypes::SequenceOfPsidSsp &psidssp_seq, std::string &psidssp_str)
{
	DEBUGC_STREAM_CALLED;

	char *str = strdup(psidssp_str.c_str());
	char *token = strtok(str, ",");
	while (token)   {
		long id;
		char *sep = NULL;
		long psid = strtol(token, &sep, 10);

		if (psid == 0 || sep == NULL || *sep != ':')   {
			ERROR_STREAMC << "cannot parse psid-ssp string '" << token << "'" << std::endl;
			break;
		}
		sep++;

		char *star = strchr(sep, '*');
		std::string opaque, bitmap;
		if (star)
			opaque = std::string(sep, star - sep);
		else
			bitmap = std::string(sep, strlen(sep));

		if (!AddAidSsp(psidssp_seq, psid, opaque, bitmap))   {
			ERROR_STREAMC << "cannot add psid-ssp  '" << token << "'" << std::endl;
			break;
		}
		
		token = strtok(NULL, ",");
	}
	free(str);

	DEBUGC_STREAM_RETURNS_OK;
	return (token == NULL);
};


bool
ItsPkiInternalData::getEncryptionKeyFromCertificate(OCTETSTRING &cert_raw, void **ret_key)
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
ItsPkiInternalData::getVerificationKeyFromCertificate(OCTETSTRING &cert_raw, void **ret_key)
{
	DEBUGC_STREAM_CALLED;
	
	IEEE1609dot2::CertificateBase cert = decEtsiTs103097Certificate(cert_raw);
	if (!cert.toBeSigned().verifyKeyIndicator().ischosen(IEEE1609dot2::VerificationKeyIndicator::ALT_verificationKey))   {
		ERROR_STREAMC << "Not supported Verification Key Indicator type: " << cert.toBeSigned().verifyKeyIndicator().get_selection() << std::endl;
		return false;
	}
	IEEE1609dot2BaseTypes::PublicVerificationKey pubKey = cert.toBeSigned().verifyKeyIndicator().verificationKey();

	int nid;
	IEEE1609dot2BaseTypes::EccP256CurvePoint ecCurvePointP256;
	IEEE1609dot2BaseTypes::EccP384CurvePoint ecCurvePointP384;
	if (pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaNistP256))   {
		DEBUGC_STREAM << "Verification key NistP256" << std::endl;
		ecCurvePointP256 = pubKey.ecdsaNistP256();
		nid = NID_X9_62_prime256v1;
	}
	else if (pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaBrainpoolP256r1))   {
		DEBUGC_STREAM << "Verification key BrainpoolP256r1" << std::endl;
		ecCurvePointP256 = pubKey.ecdsaBrainpoolP256r1();
		nid = NID_brainpoolP256r1;
	}
	else if (pubKey.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaBrainpoolP384r1))   {
		DEBUGC_STREAM << "Verification key BrainpoolP384r1" << std::endl;
		ecCurvePointP384 = pubKey.ecdsaBrainpoolP384r1();
		nid = NID_brainpoolP384r1;
	}
	else   {
		ERROR_STREAMC << "ItsPkiInternalData::setEncryptionKey() invalid EC key type" << std::endl;
		return false;
	}

	int y_bit = -1;
	OCTETSTRING comp, x, y;
	if (nid == NID_X9_62_prime256v1 || nid == NID_brainpoolP256r1)   {
		if (ecCurvePointP256.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__0))   {
			comp = ecCurvePointP256.compressed__y__0();
			y_bit = 0;
		}
		else if (ecCurvePointP256.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__1))   {
			comp = ecCurvePointP256.compressed__y__1();
			y_bit = 1;
		}
		else if (ecCurvePointP256.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_uncompressedP256))   {
			x = ecCurvePointP256.uncompressedP256().x();
			y = ecCurvePointP256.uncompressedP256().y();
		}
		else   {
			ERROR_STREAMC << "unsupported EccP256CurvePoint choice" << std::endl;
			return false;
		}
	}
	else   {
		if (ecCurvePointP384.ischosen(IEEE1609dot2BaseTypes::EccP384CurvePoint::ALT_compressed__y__0))   {
			comp = ecCurvePointP384.compressed__y__0();
			y_bit = 0;
		}
		else if (ecCurvePointP384.ischosen(IEEE1609dot2BaseTypes::EccP384CurvePoint::ALT_compressed__y__1))   {
			comp = ecCurvePointP384.compressed__y__1();
			y_bit = 1;
		}
		else if (ecCurvePointP384.ischosen(IEEE1609dot2BaseTypes::EccP384CurvePoint::ALT_uncompressedP384))   {
			x = ecCurvePointP384.uncompressedP384().x();
			y = ecCurvePointP384.uncompressedP384().y();
		}
		else   {
			ERROR_STREAMC << "unsupported EccP384CurvePoint choice" << std::endl;
			return false;
		}
	}

	if (!ECKey_PublicKeyFromComponents(nid, x, y, comp, y_bit, ret_key))   {
		ERROR_STREAMC << "ItsPkiInternalData::setEncryptionKey() failed to set EC PublicKey from componets" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::SetEAEncryptionKey(OCTETSTRING &cert_blob)
{
	DEBUGC_STREAM_CALLED;

	if (!getEtsiTs103097CertId(cert_blob, eaId))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setEACertificate() cannot set ID of EA certificate" << std::endl;
		return false;
	}
	dump_ttcn_object(eaId, "EA ID: ");

	eaCert_blob = cert_blob;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::SetAAEncryptionKey(OCTETSTRING &cert_blob)
{
	DEBUGC_STREAM_CALLED;
	
	if (!getEtsiTs103097CertId(cert_blob, aaId))   {
		DEBUGC_STREAM << "ItsPkiInternalData::setAACertificate() cannot set ID of AA certificate" << std::endl;
		return false;
	}
	dump_ttcn_object(aaId, "AA ID: ");
	
	aaCert_blob = cert_blob;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::SetItsEcId(OCTETSTRING &cert_blob)
{
	DEBUGC_STREAM_CALLED;
	
	if (!getEtsiTs103097CertId(cert_blob, itsEcId))   {
		DEBUGC_STREAM << "ItsPkiInternalData::getCertId(() cannot set Its Ec ID" << std::endl;
		return false;
	}

	dump_ttcn_object(itsEcId, "Its Ec ID: ");
	
	itsEcCert_blob = cert_blob;
	
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
	hash_algorithm = IEEE1609dot2BaseTypes::HashAlgorithm::UNBOUND_VALUE;
}


bool
ItsPkiInternalData::CheckItsRegisterData()
{
	DEBUGC_STREAM_CALLED;

        if (profile.empty())   {
		ERROR_STREAM << "Its register: missing or invalid 'profile'" << std::endl;
		return false;
	}
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::CheckEnrollmentDataEA()
{
	DEBUGC_STREAM_CALLED;

	if (!eaCert_blob.is_bound() || eaCert_blob.lengthof() == 0)   {
		ERROR_STREAMC << "invalid EA certificate blob" << std::endl;
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
#if 0
	if (aaEncryptionKey == NULL)   {
		ERROR_STREAMC << "AA encryption key do not set" << std::endl;
		return false;
	}
#endif
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
		ERROR_STREAMC << "missing ITS EC ID" << std::endl;
		return false;
	}

	if (!itsEcCert_blob.is_bound() || itsEcCert_blob.lengthof() == 0)   {
		ERROR_STREAMC << "missing ITS EC certificatge blob" << std::endl;
		return false;
	}
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiInternalData::CheckEcEnrollmentArguments()
{
	DEBUGC_STREAM_CALLED;
	
	if (!CheckEnrollmentDataEA())   {
		ERROR_STREAMC << "EC enroll: invalid EA parameters" << std::endl;
		return false;
	}
	if (!EcCheckAidSsp())   {
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

	if (!CheckEnrollmentDataEA())   {
		ERROR_STREAMC << "At enroll: invalid EA parameters" << std::endl;
		return false;
	}
	if (!CheckEnrollmentDataAA())   {
		ERROR_STREAMC << "At enroll: invalid AA parameters" << std::endl;
		return false;
	}
	if (!AtCheckAidSsp())   {
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
