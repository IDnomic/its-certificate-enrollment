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
    	std::string its_canonical_id;
    	std::string its_name_header;
	std::string profile;
	
	struct PsidSsp psid_ssp;
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
	
	std::string itsEcCertSave2File;
	std::string itsEcVerificationKeySave2File;
	std::string itsEcEncryptionKeySave2File;

	OCTETSTRING itsAtCert_blob;
	OCTETSTRING itsAtId;
	void *itsAtVerificationKey = NULL;
	void *itsAtEncryptionKey = NULL;
	bool itsAtEncryptionKeyEnable = false;

	std::string itsAtCertFile;
	std::string itsAtVerificationKeyFile;
	std::string itsAtEncryptionKeyFile;

	std::string itsAtCertSave2File;
	std::string itsAtVerificationKeySave2File;
	std::string itsAtEncryptionKeySave2File;

	std::string hexeaid;
	OCTETSTRING eaId;
	OCTETSTRING eaCert_blob;
	void *eaEncryptionKey = NULL;
	void *eaVerificationKey = NULL;

	std::string hexaaid;
	OCTETSTRING aaId;
	OCTETSTRING aaCert_blob;
	void *aaEncryptionKey = NULL;
	void *aaVerificationKey = NULL;

	void init();

	bool setEncryptionKey(OCTETSTRING &, void **);
	// bool getCertId(OCTETSTRING &, OCTETSTRING &);

	bool CheckEnrollmentDataEA();
	bool CheckEnrollmentDataAA();
	bool CheckEnrollmentDataItsEc();
public:
	ItsPkiInternalData();
	~ItsPkiInternalData();
	const char *GetClassName() {return CLASS_NAME.c_str();};
	
	bool SetItsNameHeader(const std::string &);
	std::string GetItsNameHeader() { return its_name_header; };

	bool SetCanonicalID(const std::string &, const std::string &, void *);
	std::string GetCanonicalId() { return its_canonical_id; };

	bool SetProfile(const std::string &_profile) {profile = _profile; return true;};
	std::string GetProfile() { return profile; };

	bool SetAidSsp(const long, const std::string &, const std::string &);
	struct PsidSsp &GetAppPermsSsp() { return psid_ssp; };
	bool CheckAidSsp();
	
	bool SetHashAlgorithm(IEEE1609dot2BaseTypes::HashAlgorithm::enum_type algo) {
		hash_algorithm = algo;
		return true;
	};
	IEEE1609dot2BaseTypes::HashAlgorithm::enum_type &GetHashAlgorithm() { return hash_algorithm; };

	bool SetItsTechnicalKey(void *key) {
		technicalKey = key;
		return (key != NULL);
	};
	void *GetItsTechnicalKey() {
		return technicalKey;
	};

	void SetItsEcVerificationKey(void *key) {
		itsEcVerificationKey = key;
	};
	void *GetItsEcVerificationKey() {
		return itsEcVerificationKey;
	};
	
	void SetItsEcEncryptionKey(void *key) {
		itsEcEncryptionKey = key;
		if (key != NULL) itsEcEncryptionKeyEnable = true;
	};
	void SetItsEcEncryptionKeyEnable(bool enable) {
		itsEcEncryptionKeyEnable = enable;
	}
	void *GetItsEcEncryptionKey() {
		return (itsEcEncryptionKeyEnable ? itsEcEncryptionKey : NULL);
	};
	bool IsItsEcEncryptionKeyEnabled() {
		return itsEcEncryptionKeyEnable;
	}

	bool SetEAEncryptionKey(OCTETSTRING &);

	bool SetItsEcCertSave2File(std::string file_name) {
		itsEcCertSave2File = file_name;
       		return true;
	};
	std::string &GetItsEcCertSave2File() {
		return itsEcCertSave2File;
	};

	bool SetItsEcVerificationKeySave2File(std::string file_name) {
		itsEcVerificationKeySave2File = file_name;
       		return true;
	};
	std::string &GetItsEcVerificationKeySave2File() {
		return itsEcVerificationKeySave2File;
	};
	
	bool SetItsEcEncryptionKeySave2File(std::string file_name) {
		itsEcEncryptionKeySave2File = file_name;
       		return true;
	};
	std::string &GetItsEcEncryptionKeySave2File() {
		return itsEcEncryptionKeySave2File;
	};

	void SetItsAtVerificationKey(void *key) {
		itsAtVerificationKey = key;
	};
	void *GetItsAtVerificationKey() {
		return itsAtVerificationKey;
	};
	
	void SetItsAtEncryptionKey(void *key) {
		itsAtEncryptionKey = key;
		if (key != NULL) itsAtEncryptionKeyEnable = true;
	};
	void *GetItsAtEncryptionKey() {
		return (itsAtEncryptionKeyEnable ? itsAtEncryptionKey : NULL);
	};
	void SetItsAtEncryptionKeyEnable(bool enable) {
		itsAtEncryptionKeyEnable = enable;
	}
	bool IsItsAtEncryptionKeyEnabled() {
		return itsAtEncryptionKeyEnable;
	}




	bool SetAAEncryptionKey(OCTETSTRING &);

	bool SetItsEcId(OCTETSTRING &);

	bool SetItsAtCertSave2File(std::string file_name) {
		itsAtCertSave2File = file_name;
       		return true;
	};
	std::string &GetItsAtCertSave2File() {
		return itsAtCertSave2File;
	};

	bool SetItsAtVerificationKeySave2File(std::string file_name) {
		itsAtVerificationKeySave2File = file_name;
       		return true;
	};
	std::string &GetItsAtVerificationKeySave2File() {
		return itsAtVerificationKeySave2File;
	};
	
	bool SetItsAtEncryptionKeySave2File(std::string file_name) {
		itsAtEncryptionKeySave2File = file_name;
       		return true;
	};
	std::string &GetItsAtEncryptionKeySave2File() {
		return itsAtEncryptionKeySave2File;
	};

	bool IsItsRegistrationNeeded() { return itsNeedRegistration; };
	void SetItsRegistrationFlag(bool needed) { itsNeedRegistration = needed; };
	
	bool IsEcEnrollmentNeeded() { return itsNeedEcEnrollment; };
	void SetEcEnrollmentFlag(bool needed) { itsNeedEcEnrollment = needed; };
	
	bool CheckItsRegisterData();
	bool CheckEcEnrollmentArguments();
	bool CheckAtEnrollmentArguments();

	bool IEEE1609dot2_Sign(OCTETSTRING &, OCTETSTRING &, void *, OCTETSTRING &, OCTETSTRING &);

	OCTETSTRING &GetEAId() {
		return eaId;
	};
	OCTETSTRING &GetEACertBlob() {
		return eaCert_blob;
	};

	OCTETSTRING &GetAACertBlob() {
		return aaCert_blob;
	};

	OCTETSTRING &GetItsEcId() {
		return itsEcId;
	};
	OCTETSTRING &GetItsEcCertBlob() {
		return itsEcCert_blob;
	};

	std::string saveTechnicalKeyFile;

	int debug = 0;
};

#endif // ifndef ITS_PKI_INTERNAL_DATA_HH
