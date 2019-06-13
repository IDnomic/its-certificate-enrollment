#ifndef ITS_PKI_INTERNAL_DATA_HH
#define ITS_PKI_INTERNAL_DATA_HH

#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>

#include <openssl/objects.h>

#include "TTCN3.hh"
#include "EtsiTs103097Module.hh"

#include "its-asn1-modules.hh"

#include "pki-its-cmd-args.hh"
#include "pki-its-internal-data.hh"

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
	std::string last_error_str;

	unsigned char its_id[8];
	std::string log_line_header;

	unsigned char *ecid = NULL;
    	std::string its_canonical_id;
	std::string profile;
	
	struct PsidSsp psid_ssp;
	IEEE1609dot2BaseTypes::HashAlgorithm::enum_type hash_algorithm;
	
	unsigned char *validityrestrictions = NULL;
	int validityrestrictions_len;
	
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
	bool ParseEcEnrollmentCmdArguments(ItsPkiCmdArguments &);
	bool ParseCmdArguments(ItsPkiCmdArguments &);
	bool CreateCanonicalID(ItsPkiCmdArguments &);
	bool BuildAidSsp(ItsPkiCmdArguments &);
	bool setEncryptionKey(OCTETSTRING &, void **);
	bool setEAEncryptionKey(OCTETSTRING &);
	bool readEACertificateFile(std::string &);
	bool readEACertificateB64(std::string &);
	bool setAAEncryptionKey(OCTETSTRING &);
	bool readAACertificateFile(std::string &);
	bool readAACertificateB64(std::string &);
	bool readItsEcCertificateFile(std::string &);
	bool readItsEcCertificateB64(std::string &);
	bool setItsEcId(OCTETSTRING &);
public:
	ItsPkiInternalData(ItsPkiCmdArguments &);
	ItsPkiInternalData(type_cmd_operation_t cmd, ItsPkiCmdArguments &);
		
	ItsPkiInternalData() = delete;
	~ItsPkiInternalData();
	const char *GetClassName() {return CLASS_NAME.c_str();};

	bool IsValid() { return valid; };	
	bool GetItsRegisterRequest(std::string &);
	std::string GetLastErrorStr() { return last_error_str; };
	std::string GetCanonicalId() { return its_canonical_id; };
	struct PsidSsp &GetAppPermsSsp() { return psid_ssp; };
	IEEE1609dot2BaseTypes::HashAlgorithm::enum_type &GetHashAlgorithm() { return hash_algorithm; };
	bool IEEE1609dot2_Sign(OCTETSTRING &, OCTETSTRING &, void *, OCTETSTRING &, OCTETSTRING &);

	void *GetItsEcVerificationKey() { return itsEcVerificationKey; };
	void *GetItsEcEncryptionKey() { return (itsEcEncryptionKeyEnable ? itsEcEncryptionKey : NULL); };
	void *GetItsAtVerificationKey() { return itsAtVerificationKey; };
	void *GetItsAtEncryptionKey() { return (itsAtEncryptionKeyEnable ? itsAtEncryptionKey : NULL); };
	void *GetItsTechnicalKey() { return technicalKey; };

	bool GetPublicVerificationKey(void *, IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetItsEcPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetItsAtPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetPublicEncryptionKey(void *, IEEE1609dot2BaseTypes::PublicEncryptionKey &);
	bool GetItsEcPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &);
	bool GetItsAtPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &);
	OCTETSTRING &GetEAId() { return eaId; };
	OCTETSTRING &GetEACertBlob() { return eaCert_blob;};
	OCTETSTRING &GetAAId() { return aaId; };
	OCTETSTRING &GetAACertBlob() { return aaCert_blob;};

	OCTETSTRING &GetItsEcId() { return itsEcId; };
	OCTETSTRING &GetItsEcCertBlob() { return itsEcCert_blob; };
	std::string &GetItsEcCertSave2File() { return itsEcCertSave2File; };
	std::string &GetItsEcVerificationKeySave2File() { return itsEcVerificationKeySave2File; };
	std::string &GetItsEcEncryptionKeySave2File() { return itsEcEncryptionKeySave2File; };

	OCTETSTRING &GetItsAtId() { return itsAtId; };
	OCTETSTRING &GetItsAtCertBlob() { return itsAtCert_blob; };
	std::string &GetItsAtCertSave2File() { return itsAtCertSave2File; };
	std::string &GetItsAtVerificationKeySave2File() { return itsAtVerificationKeySave2File; };
	std::string &GetItsAtEncryptionKeySave2File() { return itsAtEncryptionKeySave2File; };

	bool setCertId(OCTETSTRING &, OCTETSTRING &);

	std::string saveTechnicalKeyFile;
    	void *technicalKey = NULL;

	int debug = 0;
};

#endif // ifndef ITS_PKI_INTERNAL_DATA_HH
