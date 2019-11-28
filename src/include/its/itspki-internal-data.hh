#ifndef ITS_PKI_INTERNAL_DATA_HH
#define ITS_PKI_INTERNAL_DATA_HH

#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>

#include <openssl/objects.h>

#include "TTCN3.hh"
#include "EtsiTs103097Module.hh"

#include "its/its-asn1-modules.hh"

#include <IEEE1609dot2BaseTypes.hh>

#define DEFAULT_ITS_CANONICAL_ID_HEADER "BENCH-SCOOP-ITS"
#define DEFAULT_ITS_EC_CERT_DURATION_YEARS (3)
#define DEFAULT_ITS_AT_CERT_DURATION_MINS (60*24)

class ItsPkiInternalData {
public:
	struct PsidSsp {
		long psid;
		IEEE1609dot2BaseTypes::ServiceSpecificPermissions::union_selection_type type;
		OCTETSTRING ssp;
	};

	enum ServiceSpecificPermissionsChoice {
		Opaque = 1,
		BitmapSSP,
	};

	enum CertificateFormat {
		ts103097v131 = 1,
	};

private:
	std::string CLASS_NAME = std::string("ItsPkiInternalData");
	bool valid = false;

	unsigned char its_id[8];
	std::string log_line_header;

	unsigned char *ecid = NULL;

	IEEE1609dot2BaseTypes::Duration ItsEcCertDuration;
	int ItsEcCertValidFrom = 0;

	IEEE1609dot2BaseTypes::Duration ItsAtCertDuration;
	int ItsAtCertValidFrom = 0;

	OCTETSTRING its_cid;
	std::string its_pid;
	OCTETSTRING its_sid;
	bool generate_its_sid = false;

	std::string profile;
	
	IEEE1609dot2BaseTypes::SequenceOfPsidSsp ec_ssp_seq;
	IEEE1609dot2BaseTypes::SequenceOfPsidSsp at_ssp_seq;

	IEEE1609dot2BaseTypes::HashAlgorithm::enum_type hash_algorithm = IEEE1609dot2BaseTypes::HashAlgorithm::sha256;
	
	unsigned char *validityrestrictions = NULL;
	int validityrestrictions_len;
	
    	void *technicalKey = NULL;
	bool itsNeedRegistration = false;

	OCTETSTRING itsEcCert_blob;
	OCTETSTRING itsEcId;

	void *itsEcVerificationKey = NULL;

	void *itsEcEncryptionKey = NULL;
	bool itsEcEncryptionKeyEnable = false;

	std::string itsEcCertFile;
	std::string itsEcVerificationKeyFile;
	std::string itsEcEncryptionKeyFile;
	bool itsNeedEcEnrollment = false;
	
	OCTETSTRING itsAtCert_blob;
	OCTETSTRING itsAtId;
	void *itsAtVerificationKey = NULL;
	void *itsAtEncryptionKey = NULL;
	bool itsAtEncryptionKeyEnable = false;

	std::string itsAtCertFile;
	std::string itsAtVerificationKeyFile;
	std::string itsAtEncryptionKeyFile;

	std::string hexeaid;
	OCTETSTRING eaId;
	OCTETSTRING eaCert_blob;

	std::string hexaaid;
	OCTETSTRING aaId;
	OCTETSTRING aaCert_blob;

	void init();

	bool CheckEnrollmentDataEA();
	bool CheckEnrollmentDataAA();
	bool CheckEnrollmentDataItsEc();
	
	bool AddAidSsp(IEEE1609dot2BaseTypes::SequenceOfPsidSsp &, const long, const std::string &, const std::string &);
	bool AddAidSsp(IEEE1609dot2BaseTypes::SequenceOfPsidSsp &, std::string &);

	bool SetDuration(int num, IEEE1609dot2BaseTypes::Duration::union_selection_type units, IEEE1609dot2BaseTypes::Duration &duration);

public:
	ItsPkiInternalData();
	~ItsPkiInternalData();
	const char *GetClassName() {return CLASS_NAME.c_str();};
	
	bool SetItsCanonicalID(const std::string &, const std::string &, const std::string &, void *);
	OCTETSTRING GetItsCanonicalId() {
		return its_cid.is_bound() ? its_cid : OCTETSTRING(0, (const unsigned char *)"");
	};
	std::string GetItsPrefixId()    { return its_pid; };
	OCTETSTRING & GetItsSerialId()    { return its_sid; };


	bool SetProfile(const std::string &_profile) {profile = _profile; return true;};
	std::string GetProfile() { return profile; };

	bool EcAddAidSsp(const long _id, const std::string &_opaque, const std::string &_bitmap) { return AddAidSsp(ec_ssp_seq, _id, _opaque, _bitmap); };
	bool EcAddAidSsp(std::string &_str) { return AddAidSsp(ec_ssp_seq, _str); };
	bool AtAddAidSsp(const long _id, const std::string &_opaque, const std::string &_bitmap) { return AddAidSsp(at_ssp_seq, _id, _opaque, _bitmap); };
	bool AtAddAidSsp(std::string &_str) { return AddAidSsp(at_ssp_seq, _str); };
	bool EcCheckAidSsp() { return (ec_ssp_seq.is_bound()) && (ec_ssp_seq.n_elem() > 0); };
	bool AtCheckAidSsp() { return (at_ssp_seq.is_bound()) && (at_ssp_seq.n_elem() > 0); };
	IEEE1609dot2BaseTypes::SequenceOfPsidSsp &EcGetAppPermsSsp() { return ec_ssp_seq; };
	IEEE1609dot2BaseTypes::SequenceOfPsidSsp &AtGetAppPermsSsp() { return at_ssp_seq; };
	
	bool SetHashAlgorithm(IEEE1609dot2BaseTypes::HashAlgorithm::enum_type algo) {
		hash_algorithm = algo;
		return true;
	};
	IEEE1609dot2BaseTypes::HashAlgorithm::enum_type &GetHashAlgorithm() { return hash_algorithm; };

	bool SetItsTechnicalKey(void *key) {
		technicalKey = key;
		return (key != NULL);
	};
	void *GetItsTechnicalKey() { return technicalKey; };

	void SetItsEcVerificationKey(void *key) { itsEcVerificationKey = key; };
	void *GetItsEcVerificationKey() { return itsEcVerificationKey; };
	
	void SetItsEcEncryptionKey(void *key) {
		itsEcEncryptionKey = key;
		itsEcEncryptionKeyEnable = (key != NULL);
	};
	void SetItsEcEncryptionKeyEnable(bool enable) { itsEcEncryptionKeyEnable = enable; }
	void *GetItsEcEncryptionKey() { return (itsEcEncryptionKeyEnable ? itsEcEncryptionKey : NULL); };
	bool IsItsEcEncryptionKeyEnabled() { return itsEcEncryptionKeyEnable; }

	bool SetEAEncryptionKey(OCTETSTRING &);

	void SetItsAtVerificationKey(void *key) { itsAtVerificationKey = key; };
	void *GetItsAtVerificationKey() { return itsAtVerificationKey; };
	
	void SetItsAtEncryptionKey(void *key) { itsAtEncryptionKey = key;
		//itsAtEncryptionKeyEnable = (key != NULL);
	};
	void *GetItsAtEncryptionKey() { return (itsAtEncryptionKeyEnable ? itsAtEncryptionKey : NULL); };
	void SetItsAtEncryptionKeyEnable(bool enable) { itsAtEncryptionKeyEnable = enable; }
	bool IsItsAtEncryptionKeyEnabled() { return itsAtEncryptionKeyEnable; }

	bool SetAAEncryptionKey(OCTETSTRING &);

	bool SetItsEcId(OCTETSTRING &);
	bool IsItsRegistrationNeeded() { return itsNeedRegistration; };
	void SetItsRegistrationFlag(bool needed) { itsNeedRegistration = needed; };
	
	bool IsEcEnrollmentNeeded() { return itsNeedEcEnrollment; };
	void SetEcEnrollmentFlag(bool needed) { itsNeedEcEnrollment = needed; };
	
	bool CheckItsRegisterData();
	bool CheckEcEnrollmentArguments();
	bool CheckAtEnrollmentArguments();

	OCTETSTRING &GetEAId() { return eaId; };
	OCTETSTRING &GetEACertBlob() { return eaCert_blob; };
	OCTETSTRING &GetAAId() { return aaId; };
	OCTETSTRING &GetAACertBlob() { return aaCert_blob; };
	OCTETSTRING &GetItsEcId() { return itsEcId; };
	OCTETSTRING &GetItsEcCertBlob() { return itsEcCert_blob; };

	bool getEncryptionKeyFromCertificate(OCTETSTRING &, void **);
	bool getVerificationKeyFromCertificate(OCTETSTRING &, void **);

	bool IsGenerateItsSerialId()   { return generate_its_sid; };

	bool SetItsEcCertDuration(int num, IEEE1609dot2BaseTypes::Duration::union_selection_type units) { return SetDuration(num, units, ItsEcCertDuration); };
	bool SetItsAtCertDuration(int num, IEEE1609dot2BaseTypes::Duration::union_selection_type units) { return SetDuration(num, units, ItsAtCertDuration); };
	void SetItsEcCertValidFrom(int num) { ItsEcCertValidFrom = num; };
	void SetItsAtCertValidFrom(int num) { ItsAtCertValidFrom = num; };

	IEEE1609dot2BaseTypes::Duration &GetItsEcCertDuration(void) { return ItsEcCertDuration; } ;
	IEEE1609dot2BaseTypes::Duration &GetItsAtCertDuration(void) { return ItsAtCertDuration; } ;
	int GetItsEcCertValidFrom() { return ItsEcCertValidFrom; };
	int GetItsAtCertValidFrom() { return ItsAtCertValidFrom; };
	int debug = 0;
};

#endif // ifndef ITS_PKI_INTERNAL_DATA_HH
