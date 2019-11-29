#ifndef ITS_PKI_SESSION_HH
#define ITS_PKI_SESSION_HH

#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>

#include <openssl/objects.h>

#include "TTCN3.hh"
#include "EtsiTs103097Module.hh"
#include "EtsiTs102941TypesEnrolment.hh"
#include "EtsiTs102941MessagesCa.hh"

#include "its/itspki-internal-data.hh"
#include "its/itspki-etsi.hh"

class ItsPkiException : public std::exception {
private:
        static bool initialized;
public:
        static void init()  { initialized = true; };
};

class ItsPkiSession {
private:
	std::string CLASS_NAME = std::string("ItsPkiSession");
	ItsPkiEtsi etsiServices;
	ItsPkiInternalData *idata = NULL;

	void *sessionTechnicalKey = NULL;
	void *sessionItsEcVerificationKey = NULL;
	void *sessionItsEcEncryptionKey = NULL;
	void *sessionItsAtVerificationKey = NULL;
	void *sessionItsAtEncryptionKey = NULL;
	
	OCTETSTRING sessionItsEcCert;
	OCTETSTRING sessionItsEcId;
	OCTETSTRING sessionItsAtCert;

	OCTETSTRING its_cid;
	std::string its_pid;
	OCTETSTRING its_sid;

	INTEGER timeNow_InSec();
	INTEGER timeNow_InMkSec();

	bool GetPublicVerificationKey(void *, IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetPublicEncryptionKey(void *, IEEE1609dot2BaseTypes::PublicEncryptionKey &);
	bool GetItsEcPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetItsEcPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &);
	bool GetItsAtPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetItsAtPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &);

	bool GetIEEE1609dot2Signature(ItsPkiInternalData &, OCTETSTRING &, OCTETSTRING &, void *, IEEE1609dot2BaseTypes::Signature &);
	bool IEEE1609dot2_VerifySignedData(IEEE1609dot2::SignedData &signed_data, void *, IEEE1609dot2::SignedDataPayload &);

public:
	void *session_data = NULL;

	ItsPkiSession(ItsPkiInternalData &);
	~ItsPkiSession();
	const char *GetClassName() {return CLASS_NAME.c_str();};
	const char *GetIdataClassName() {return idata ? idata->GetClassName() : NULL; };
	
	std::string sessionGetProfile() { return idata->GetProfile(); } ;
	std::string sessionGetItsPrefixId() { return its_pid; } ;
	OCTETSTRING & sessionGetItsSerialId() { return its_sid; } ;
	OCTETSTRING & sessionGetItsCanonicalId();

	void sessionSetItsCanonicalId(OCTETSTRING &id) { its_cid = id; };
	void sessionSetItsSerialId(OCTETSTRING &id) { its_sid = id; };
	void sessionSetItsPrefixId(std::string &id) { its_pid = id; };

	void *sessionGenerateTechnicalKey() {
		sessionTechnicalKey = ECKey_GeneratePrivateKey();
		return sessionTechnicalKey;
	};

	void *sessionGetTechnicalKey();
	void *sessionGetItsEcVerificationKey();
	void *sessionGetItsEcEncryptionKey();
	void *sessionGetItsAtVerificationKey();
	void *sessionGetItsAtEncryptionKey();
	OCTETSTRING &sessionGetItsEcCert();
	OCTETSTRING &sessionGetItsEcId();
	OCTETSTRING &sessionGetItsAtCert() { return sessionItsAtCert; };

	bool sessionCheckEcEnrollmentArguments(ItsPkiInternalData &);
	bool sessionCheckAtEnrollmentArguments(ItsPkiInternalData &);

	ItsPkiInternalData *GetIData() { return idata;};
	OCTETSTRING request_data;

	bool EncryptSignedData_ForEa(ItsPkiInternalData &, OCTETSTRING &, OCTETSTRING &);
	bool EncryptSignedData_ForEa(ItsPkiInternalData &, OCTETSTRING &, IEEE1609dot2::Ieee1609Dot2Data &);
	bool EncryptSignedData_ForAa(ItsPkiInternalData &, OCTETSTRING &, OCTETSTRING &);
	bool EncryptSignedData_ForAa(ItsPkiInternalData &, OCTETSTRING &, IEEE1609dot2::Ieee1609Dot2Data &);

	bool EcEnrollmentRequest_Create(ItsPkiInternalData &, OCTETSTRING &);
	bool EcEnrollmentRequest_InnerEcRequest(ItsPkiInternalData &, EtsiTs102941TypesEnrolment::InnerEcRequest &);
	bool EcEnrollmentRequest_InnerData(ItsPkiInternalData &, EtsiTs102941TypesEnrolment::InnerEcRequest &, IEEE1609dot2::Ieee1609Dot2Data &);
	bool EcEnrollmentRequest_HeaderInfo(ItsPkiInternalData &, IEEE1609dot2::HeaderInfo &);
	bool EcEnrollmentResponse_Parse(OCTETSTRING &);
	bool EcEnrollmentResponse_Parse(OCTETSTRING &, OCTETSTRING &);
	bool EcEnrollmentResponse_Parse(OCTETSTRING &, OCTETSTRING &, OCTETSTRING &);
	bool EcEnrollmentResponse_Status(OCTETSTRING &);
	bool EcEnrollmentRequest_Parse(OCTETSTRING &, void *, EtsiTs102941TypesEnrolment::InnerEcRequest &);

	bool AtEnrollmentRequest_Create(ItsPkiInternalData &, OCTETSTRING &);
	bool AtEnrollmentRequest_HeaderInfo(ItsPkiInternalData &, IEEE1609dot2::HeaderInfo &);
	bool AtEnrollmentRequest_SignedExternalPayload(ItsPkiInternalData &, OCTETSTRING &, EtsiTs103097Module::EtsiTs103097Data__SignedExternalPayload &);
	bool AtEnrollmentRequest_SignedExternalPayload(ItsPkiInternalData &, EtsiTs102941TypesAuthorization::SharedAtRequest &, EtsiTs103097Module::EtsiTs103097Data__SignedExternalPayload &);
	bool AtEnrollmentRequest_POP(ItsPkiInternalData &, EtsiTs102941MessagesCa::EtsiTs102941Data &, EtsiTs103097Module::EtsiTs103097Data__Signed__My &);
	bool AtEnrollmentRequest_Parse(OCTETSTRING &, void *, void *);
	bool AtEnrollmentResponse_Parse(OCTETSTRING &, OCTETSTRING &);
	bool AtEnrollmentResponse_Status(OCTETSTRING &);

	bool IEEE1609dot2_Sign(OCTETSTRING &, OCTETSTRING &, void *, OCTETSTRING &, OCTETSTRING &);
	bool IEEE1609dot2_VerifyToBeEncoded(OCTETSTRING &, OCTETSTRING &, void *, OCTETSTRING &, OCTETSTRING &);
	
	bool IEEE1609dot2_VerifySignedData_C(IEEE1609dot2::SignedData &signed_data, void *, IEEE1609dot2::Ieee1609Dot2Content &);
	bool IEEE1609dot2_VerifySignedData_H(IEEE1609dot2::SignedData &signed_data, void *, IEEE1609dot2::HashedData &);

	bool setSKeyContext(OCTETSTRING &skey_id, OCTETSTRING &aes_key, OCTETSTRING &tag);
};
#endif // ifndef ITS_PKI_SESSION_HH
