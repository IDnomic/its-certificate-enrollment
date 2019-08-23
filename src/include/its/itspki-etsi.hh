#ifndef ITS_PKI_ETSI_SERVICES_HH
#define ITS_PKI_ETSI_SERVICES_HH

#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>
// #include <boost/program_options.hpp>

#include <openssl/objects.h>

#include "TTCN3.hh"
#include "EtsiTs103097Module.hh"
#include "EtsiTs102941TypesEnrolment.hh"
#include "EtsiTs102941MessagesCa.hh"

#include "its/utils-openssl.hh"

class ItsPkiEtsi {
private:
	std::string CLASS_NAME = std::string("ItsPkiEtsi");
	class ItsPkiPrivateKey;

	class ItsPkiPublicKey {
	private:
		std::string CLASS_NAME = std::string("ItsPkiEtsi::ItsPkiPublicKey");
		OCTETSTRING x;
		OCTETSTRING y;
		OCTETSTRING comp_key;
		INTEGER comp_key_mode;
		int nid = -1;
		friend class ItsPkiPrivateKey; 
			
		bool LoadCompressedKey(int nid, OCTETSTRING &comp_key, int comp_mode);
	public:
		bool LoadVerificationKeyFromCertificate(IEEE1609dot2::CertificateBase &cert);
		bool LoadEncryptionKeyFromCertificate(IEEE1609dot2::CertificateBase &cert);
		bool IsValid(void) {return (nid != -1);};
		int GetNID() {return nid;};
		int GetCompressedMode() {return comp_key_mode;};
		bool GetCompressed(OCTETSTRING &);
		bool GetXY(OCTETSTRING &_x, OCTETSTRING &_y);
	};

	class ItsPkiPrivateKey {
	private:
		std::string CLASS_NAME = std::string("ItsPkiEtsi::ItsPkiPrivateKey");
		int enc_algorithm = NID_aes_128_ccm;

		void *ec_key = NULL;
		
		OCTETSTRING prvkey_oct;
		ItsPkiPublicKey pubkey;

		OCTETSTRING aes_skey; 
		OCTETSTRING enc_skey; 
		OCTETSTRING tag; 
	public:
		ItsPkiPrivateKey() {};
		~ItsPkiPrivateKey() {
			ECKey_Free(ec_key);
		};
		bool IsValid(void) {
			return (pubkey.IsValid() && prvkey_oct.is_present() && (ec_key != NULL));
		};
		bool GetP256CurvePoint(IEEE1609dot2BaseTypes::EccP256CurvePoint &ret);
		bool GetEciesP256EncryptedKey(IEEE1609dot2BaseTypes::EciesP256EncryptedKey &ret);
		bool GetEncryptedDataEncryptionKey(IEEE1609dot2::EncryptedDataEncryptionKey &ret);
		bool IsPresentSKey(OCTETSTRING &);
		bool checkDecryptContext(OCTETSTRING &);

		void setAesSKey(const char *hex_value) {aes_skey = str2oct(hex_value);};
		
		bool setup(int, const char *);
		bool setup(void *key, OCTETSTRING &);
		bool generate(int);
		bool derivate(const OCTETSTRING &recipient_pubkey_x, const OCTETSTRING &recipients_pubkey_y, const OCTETSTRING &salt);
		bool encrypt(const OCTETSTRING &message, OCTETSTRING &nonce, OCTETSTRING &ret_enc_message);
		bool encrypt(const OCTETSTRING &msg, IEEE1609dot2::AesCcmCiphertext &cipher_txt);
		bool encrypt(const OCTETSTRING &msg, IEEE1609dot2::SymmetricCiphertext &cipher_txt);
		bool decryptAes128ccm(IEEE1609dot2::AesCcmCiphertext &, OCTETSTRING &);
	};
	ItsPkiPrivateKey enc_key;

	class ItsPkiRecipient {
	private:
		std::string CLASS_NAME = std::string("ItsPkiEtsi::ItsPkiRecipient");
		IEEE1609dot2::CertificateBase cert;
		OCTETSTRING cert_blob;
		OCTETSTRING cert_hash;
		OCTETSTRING hashed_id8;
		OCTETSTRING issuer_id8;
		ItsPkiPublicKey v_pub_key;
		ItsPkiPublicKey e_pub_key;

		void *e_prvkey = NULL;
		void *sender_e_pubkey = NULL;

		IEEE1609dot2BaseTypes::HashAlgorithm hash_algo = IEEE1609dot2BaseTypes::HashAlgorithm::UNKNOWN_VALUE;
	public:
		// bool setupForDecrypt(void *prvkey, void *pubkey);
		void SetPrivateKey(void *key) { e_prvkey = key; };
		void SetSenderPublicKey(void *key) { sender_e_pubkey = key; };
		void *GetPrivateKey() { return e_prvkey; };
		bool ParseCert(IEEE1609dot2::CertificateBase &cert);
		int GetVerficationNID() { return v_pub_key.GetNID(); };
		int GetEncryptionNID() { return e_pub_key.GetNID(); };
		bool GetEncryptionXY(OCTETSTRING &_x, OCTETSTRING &_y) { return e_pub_key.GetXY(_x, _y); };
		bool GetVerificationXY(OCTETSTRING &_x, OCTETSTRING &_y) { return v_pub_key.GetXY(_x, _y); };
		bool GetCertHash(OCTETSTRING &ret);
		bool GetHashedID8(OCTETSTRING &ret);
	};
	ItsPkiRecipient recipient;

	bool ready = false;
public:
	ItsPkiEtsi() {
		OpenSSL_setup();
	};

	~ItsPkiEtsi();

	// bool setRecipient(IEEE1609dot2::CertificateBase &, void *);
	bool setRecipient(OCTETSTRING &, void *);
	bool setDecryptContext(void *, void *);
	bool setup_decrypt(OCTETSTRING &);
	// bool EncryptPayload(IEEE1609dot2::CertificateBase &, OCTETSTRING &, EtsiTs103097Module::EtsiTs103097Data__Encrypted__My &);
	bool EncryptPayload(OCTETSTRING &, EtsiTs103097Module::EtsiTs103097Data__Encrypted__My &);
	bool DecryptPayload(OCTETSTRING &, OCTETSTRING &);
	bool DecryptPayload(EtsiTs103097Module::EtsiTs103097Data__Encrypted__My &, OCTETSTRING &);
	int GetRecipientEncryptionNID() { return recipient.GetEncryptionNID(); };
};

#endif // ifndef ITS_PKI_ETSI_SERVICES_HH
