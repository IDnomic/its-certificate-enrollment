#ifndef ITS_PKI_SESSION_HH
#define ITS_PKI_SESSION_HH

#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>
#include <boost/program_options.hpp>

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
	std::string its_id;

	bool GetPublicVerificationKey(void *, IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetPublicEncryptionKey(void *, IEEE1609dot2BaseTypes::PublicEncryptionKey &);
	bool GetItsEcPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetItsEcPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &);
	bool GetItsAtPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &);
	bool GetItsAtPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &);

	bool GetIEEE1609dot2Signature(ItsPkiInternalData &, OCTETSTRING &, OCTETSTRING &, void *, IEEE1609dot2BaseTypes::Signature &);

public:
	void *session_data = NULL;

	ItsPkiSession(ItsPkiInternalData &);
	~ItsPkiSession();
	const char *GetClassName() {return CLASS_NAME.c_str();};
	const char *GetIdataClassName() {return idata ? idata->GetClassName() : NULL; };
	
	void *sessionGetTechnicalKey();
	void *sessionGetItsEcVerificationKey();
	void *sessionGetItsEcEncryptionKey();
	void *sessionGetItsAtVerificationKey();
	void *sessionGetItsAtEncryptionKey();

	std::string sessionGetCanonicalId(ItsPkiInternalData &);
	std::string sessionGetItsID() { return its_id; };
	bool sessionCheckEcEnrollmentArguments(ItsPkiInternalData &);

	ItsPkiInternalData *GetIData() { return idata;};
	OCTETSTRING request_data;

	bool EncryptSignedData_ForEa(ItsPkiInternalData &, OCTETSTRING &, OCTETSTRING &);
	bool EncryptSignedData_ForEa(ItsPkiInternalData &, OCTETSTRING &, IEEE1609dot2::Ieee1609Dot2Data &);
	bool EncryptSignedData_ForAa(ItsPkiInternalData &, OCTETSTRING &, OCTETSTRING &);
	bool EncryptSignedData_ForAa(ItsPkiInternalData &, OCTETSTRING &, IEEE1609dot2::Ieee1609Dot2Data &);

	bool ItsRegisterRequest_Create(ItsPkiInternalData &, OCTETSTRING &);
	bool ItsRegisterResponse_Parse(OCTETSTRING &, OCTETSTRING &);
	bool ItsRegisterResponse_SaveToFiles(ItsPkiInternalData &, OCTETSTRING &);

	bool EcEnrollmentRequest_Create(ItsPkiInternalData &, OCTETSTRING &);
	bool EcEnrollmentRequest_InnerEcRequest(ItsPkiInternalData &, EtsiTs102941TypesEnrolment::InnerEcRequest &);
	bool EcEnrollmentRequest_InnerData(ItsPkiInternalData &, EtsiTs102941TypesEnrolment::InnerEcRequest &, IEEE1609dot2::Ieee1609Dot2Data &);
	bool EcEnrollmentRequest_HeaderInfo(ItsPkiInternalData &, IEEE1609dot2::HeaderInfo &);
	bool EcEnrollmentResponse_Parse(OCTETSTRING &, OCTETSTRING &);
	bool EcEnrollmentResponse_Status(OCTETSTRING &);
	bool EcEnrollmentResponse_SaveToFiles(ItsPkiInternalData &, OCTETSTRING &);

	bool AtEnrollmentRequest_InnerAtRequest(ItsPkiInternalData &, OCTETSTRING &);
	bool AtEnrollmentRequest_HeaderInfo(ItsPkiInternalData &, IEEE1609dot2::HeaderInfo &);
	bool AtEnrollmentRequest_SignedExternalPayload(ItsPkiInternalData &, OCTETSTRING &, EtsiTs103097Module::EtsiTs103097Data__SignedExternalPayload &);
	bool AtEnrollmentRequest_SignedExternalPayload(ItsPkiInternalData &, EtsiTs102941TypesAuthorization::SharedAtRequest &, EtsiTs103097Module::EtsiTs103097Data__SignedExternalPayload &);
	bool AtEnrollmentRequest_POP(ItsPkiInternalData &, EtsiTs102941MessagesCa::EtsiTs102941Data &, EtsiTs103097Module::EtsiTs103097Data__Signed__My &);
	bool AtEnrollmentResponse_Parse(OCTETSTRING &, OCTETSTRING &);
	bool AtEnrollmentResponse_Status(OCTETSTRING &);
	bool AtEnrollmentResponse_SaveToFiles(ItsPkiInternalData &, OCTETSTRING &);
};


#endif // ifndef ITS_PKI_SESSION_HH
