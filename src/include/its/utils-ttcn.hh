#ifndef UTILS_TTCN_HH
#define UTILS_TTCN_HH

#include <string>
#include <iostream>
#include <memory>

#include "TTCN3.hh"
#include "EtsiTs103097Module.hh"
#include "EtsiTs102941MessagesCa.hh"
#include "EtsiTs102941TypesAuthorization.hh"
#include "EtsiTs102941TypesEnrolment.hh"


bool dump_ttcn_object(Base_Type &, const char *);

// extern pthread_mutex_t mutex_encode_request;

bool getEtsiTs103097CertId(OCTETSTRING &, OCTETSTRING &);

IEEE1609dot2::CertificateBase decEtsiTs103097Certificate(const OCTETSTRING &);
IEEE1609dot2::Ieee1609Dot2Data decIeee1609Dot2Data(const OCTETSTRING &);
EtsiTs102941MessagesCa::EtsiTs102941Data decEtsiTs102941Data(const OCTETSTRING &);
EtsiTs102941TypesAuthorization::InnerAtResponse decInnerAtResponse(const OCTETSTRING &);
EtsiTs103097Module::EtsiTs103097Data__Signed__My decEtsiTs103097DataSigned(const OCTETSTRING &);
EtsiTs103097Module::EtsiTs103097Data__Encrypted__My decEtsiTs103097DataEncrypted(const OCTETSTRING &);

inline bool encEtsiTs102941Data(EtsiTs102941MessagesCa::EtsiTs102941Data &obj, OCTETSTRING &ret) {
	EtsiTs102941MessagesCa::EtsiTs102941Data_encoder(obj, ret, "OER");
	return ret.is_bound();
};
inline bool encEtsiTs103097Certificate(EtsiTs103097Module::EtsiTs103097Certificate &obj, OCTETSTRING &ret)  {
	EtsiTs103097Module::EtsiTs103097Certificate_encoder(obj, ret, "OER");
	return ret.is_bound();
};
inline bool encToBeSignedData(IEEE1609dot2::ToBeSignedData &obj, OCTETSTRING &ret) {
	TTCN_Buffer ttcn_buf;
	obj.OER_encode(IEEE1609dot2::ToBeSignedData_descr_, ttcn_buf);
	ttcn_buf.get_string(ret);
	return ret.is_bound();
};
inline bool encIeee1609Dot2Data(IEEE1609dot2::Ieee1609Dot2Data &obj, OCTETSTRING &ret) {
	IEEE1609dot2::Ieee1609Dot2Data_encoder(obj, ret, "OER");
	return ret.is_bound();
};
inline bool encInnerEcRequest(EtsiTs102941TypesEnrolment::InnerEcRequest &obj, OCTETSTRING &ret) {
	TTCN_Buffer ttcn_buf;
	obj.OER_encode(EtsiTs102941TypesEnrolment::InnerEcRequest_descr_, ttcn_buf);
	ttcn_buf.get_string(ret);
	return ret.is_bound();
};
inline bool encPublicVerificationKey(IEEE1609dot2BaseTypes::PublicVerificationKey &obj, OCTETSTRING &ret) {
	IEEE1609dot2BaseTypes::PublicVerificationKey_encoder(obj, ret, "OER");
	return ret.is_bound();
};
inline bool encPublicEncryptionKey(IEEE1609dot2BaseTypes::PublicEncryptionKey &obj, OCTETSTRING &ret) {
	IEEE1609dot2BaseTypes::PublicEncryptionKey_encoder(obj, ret, "OER");
	return ret.is_bound();
};
inline bool encSharedAtRequest(EtsiTs102941TypesAuthorization::SharedAtRequest &obj, OCTETSTRING &ret) {
	EtsiTs102941TypesAuthorization::SharedAtRequest_encoder(obj, ret, "OER");
	return ret.is_bound();
};
inline bool encSignedExternalPayload(EtsiTs103097Module::EtsiTs103097Data__SignedExternalPayload &obj, OCTETSTRING &ret) {
	EtsiTs103097Module::EtsiTs103097Data__SignedExternalPayload_encoder(obj, ret, "OER");
	return ret.is_bound();
};
inline bool encEtsiTs103097Data__Signed__My(EtsiTs103097Module::EtsiTs103097Data__Signed__My &obj, OCTETSTRING &ret)  {
	EtsiTs103097Module::EtsiTs103097Data__Signed__My_encoder(obj, ret, "OER");
	return ret.is_bound();
};
inline bool encSymmetricEncryptionKey(IEEE1609dot2BaseTypes::SymmetricEncryptionKey &obj, OCTETSTRING &ret)  {
	IEEE1609dot2BaseTypes::SymmetricEncryptionKey_encoder(obj, ret, "OER");
	return ret.is_bound();
}
inline bool encSymmetricCiphertext(IEEE1609dot2::SymmetricCiphertext &obj, OCTETSTRING &ret)  {
	IEEE1609dot2::SymmetricCiphertext_encoder(obj, ret, "OER");
	return ret.is_bound();
}

#endif // UTILS_TTCN_HH
