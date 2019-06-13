#ifndef ITS_PKI_WORK_HH
#define ITS_PKI_WORK_HH

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
#include "pki-its-internal-data.hh"
#include "pki-its-etsi.hh"
// #include "pki-its-report.hh"

class ItsPkiException : public std::exception {
private:
        static bool initialized;
public:
        static void init()  { initialized = true; };
};

class ItsPkiWork {
private:
	std::string CLASS_NAME = std::string("ItsPkiWork");
	ItsPkiEtsi etsiServices;
	ItsPkiInternalData *idata = NULL;

public:
	void *work_data = NULL;

	ItsPkiWork(ItsPkiInternalData &);
	~ItsPkiWork();
	const char *GetClassName() {return CLASS_NAME.c_str();};
	const char *GetIdataClassName() {return idata ? idata->GetClassName() : NULL; };
	
	ItsPkiInternalData *GetIData() { return idata;};
	OCTETSTRING request_data;

	bool ItsRegister(ItsPkiInternalData &);
	
	bool GetIEEE1609dot2Signature(ItsPkiInternalData &, OCTETSTRING &, OCTETSTRING &, void *, IEEE1609dot2BaseTypes::Signature &);

	bool EncryptSignedData_ForEa(ItsPkiInternalData &, OCTETSTRING &, OCTETSTRING &);
	bool EncryptSignedData_ForEa(ItsPkiInternalData &, OCTETSTRING &, IEEE1609dot2::Ieee1609Dot2Data &);
	bool EncryptSignedData_ForAa(ItsPkiInternalData &, OCTETSTRING &, OCTETSTRING &);
	bool EncryptSignedData_ForAa(ItsPkiInternalData &, OCTETSTRING &, IEEE1609dot2::Ieee1609Dot2Data &);

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


#endif // ifndef ITS_PKI_WORK_HH
