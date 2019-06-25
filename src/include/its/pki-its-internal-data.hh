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
#include "its/pki-its-internal-data.hh"

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
	std::string profile;
	
	struct PsidSsp psid_ssp;
	IEEE1609dot2BaseTypes::HashAlgorithm::enum_type hash_algorithm = IEEE1609dot2BaseTypes::HashAlgorithm::sha256;
	
	unsigned char *validityrestrictions = NULL;
	int validityrestrictions_len;
	
    	void *technicalKey = NULL;

	OCTETSTRING itsEcCert_blob;
	OCTETSTRING itsEcId;
	void *itsEcVerificationKey = NULL;
	void *itsEcEncryptionKey = NULL;
	bool itsEcEncryptionKeyEnable = false;

	std::string itsEcCertFile;
	std::string itsEcVerificationKeyFile;
	std::string itsEcEncryptionKeyFile;
	
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
	bool getCertId(OCTETSTRING &, OCTETSTRING &);
	bool GetPublicVerificationKey(void *, IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetPublicEncryptionKey(void *, IEEE1609dot2BaseTypes::PublicEncryptionKey &);

	bool CheckEnrollmentDataEA();
	bool CheckEnrollmentDataAA();
	bool CheckEnrollmentDataItsEc();
public:
	ItsPkiInternalData();
	~ItsPkiInternalData();
	const char *GetClassName() {return CLASS_NAME.c_str();};
	
	bool SetCanonicalID(const std::string &, const std::string &);
	std::string GetCanonicalId() { return its_canonical_id; };
	
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
		return technicalKey == NULL ? false : true;
	};
	void *GetItsTechnicalKey() {
		return technicalKey;
	};

	bool SetItsEcVerificationKey(void *key) {
		itsEcVerificationKey = key;
		return ((key == NULL) ? false : true);
	};
	void *GetItsEcVerificationKey() {
		return itsEcVerificationKey;
	};
	
	bool SetItsEcEncryptionKey(void *key) {
		itsEcEncryptionKey = key;
		itsEcEncryptionKeyEnable = ((key == NULL) ? false : true);
		return itsEcEncryptionKeyEnable;
	};
	void *GetItsEcEncryptionKey() {
		return (itsEcEncryptionKeyEnable ? itsEcEncryptionKey : NULL);
	};

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

	bool CheckEcEnrollmentArguments();

	bool SetItsAtVerificationKey(void *key) {
		itsAtVerificationKey = key;
		return ((key == NULL) ? false : true);
	};
	void *GetItsAtVerificationKey() {
		return itsAtVerificationKey;
	};
	
	bool SetItsAtEncryptionKey(void *key) {
		itsAtEncryptionKey = key;
		itsAtEncryptionKeyEnable = ((key == NULL) ? false : true);
		return itsAtEncryptionKeyEnable;
	};
	void *GetItsAtEncryptionKey() {
		return (itsAtEncryptionKeyEnable ? itsAtEncryptionKey : NULL);
	};

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

	bool CheckAtEnrollmentArguments();
	
	bool GetItsRegisterRequest(std::string &);
	bool IEEE1609dot2_Sign(OCTETSTRING &, OCTETSTRING &, void *, OCTETSTRING &, OCTETSTRING &);

	bool GetItsEcPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetItsAtPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetItsEcPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &);
	bool GetItsAtPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &);

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
