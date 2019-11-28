#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>
#include <memory>
// #include <boost/program_options.hpp>
 
#include <openssl/ec.h>
#include <openssl/err.h>
#include "openssl/conf.h"
#include "openssl/err.h"
#include "openssl/engine.h"
#include "openssl/ssl.h"

#include "TTCN3.hh"
#include "EtsiTs103097Module.hh"
#include "EtsiTs102941MessagesCa.hh"

#include "its/utils.hh"
#include "its/itspki-debug.hh"
#include "its/itspki-etsi.hh"
#include "its/its-asn1-modules.hh"


bool
ItsPkiEtsi::ItsPkiPublicKey::LoadCompressedKey(int in_nid, OCTETSTRING &in_comp_key, int in_comp_mode)
{
	if (!ECKey_DecompressPublicKey(in_nid, in_comp_key, in_comp_mode, x, y))   {
		ERROR_STREAMC << "cannot " << std::endl;
		return false;
	}

	comp_key_mode = INTEGER(in_comp_mode);
	comp_key = in_comp_key;
	nid = in_nid;
	
	return true;
}


bool
ItsPkiEtsi::ItsPkiPublicKey::LoadVerificationKeyFromCertificate(IEEE1609dot2::CertificateBase &in_cert)
{
	DEBUGC_STREAM_CALLED;
	
	if (!in_cert.is_present())   {
		ERROR_STREAMC << "invalid argument" << std::endl;
		return false;
	}

	IEEE1609dot2BaseTypes::PublicVerificationKey v_key = in_cert.toBeSigned().verifyKeyIndicator().verificationKey();
	if (!v_key.is_present())   {
		ERROR_STREAMC << "no public verification key" << std::endl;
		return false;
	}

	if (v_key.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaNistP256)) {
		nid = OpenSSL_txt2nid("prime256v1");
		IEEE1609dot2BaseTypes::EccP256CurvePoint ec_point = v_key.ecdsaNistP256();

		if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__0)) {
			if (!LoadCompressedKey(nid, ec_point.compressed__y__0(), 0))   {
				ERROR_STREAMC << "cannot load Y0 compressed key" << std::endl;
				return false;
			}
		}
		else if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__1)) {
			if (!LoadCompressedKey(nid, ec_point.compressed__y__1(), 1))   {
				ERROR_STREAMC << "cannot load Y1 compressed key" << std::endl;
				return false;
			}
		}
		else if (v_key.ecdsaNistP256().ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_uncompressedP256)) {
			x = ec_point.uncompressedP256().x();
			y = ec_point.uncompressedP256().y();
		}
		else {
			ERROR_STREAMC << "EC point type '" << ec_point.get_selection() << "' not supported" << std::endl;
      			return false;
		}
	}
	else if (v_key.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaBrainpoolP256r1)) {
		nid = OpenSSL_txt2nid("brainpoolP256r1");
		IEEE1609dot2BaseTypes::EccP256CurvePoint ec_point = v_key.ecdsaBrainpoolP256r1();

		if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__0)) {
			if (!LoadCompressedKey(nid, ec_point.compressed__y__0(), 0))   {
				ERROR_STREAMC << "cannot load Y0 compressed key" << std::endl;
				return false;
			}
		}
		else if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__1)) {
			if (!LoadCompressedKey(nid, ec_point.compressed__y__1(), 1))   {
				ERROR_STREAMC << "cannot load Y1 compressed key" << std::endl;
				return false;
			}
		}
		else if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_uncompressedP256)) {
      			x = ec_point.uncompressedP256().x();
      			y = ec_point.uncompressedP256().y();
		}
		else   {
			ERROR_STREAMC << "EC point type '" << ec_point.get_selection() << "' not supported" << std::endl;
			return false;
		}
	}
	else if (v_key.ischosen(IEEE1609dot2BaseTypes::PublicVerificationKey::ALT_ecdsaBrainpoolP384r1)) {
		nid = OpenSSL_txt2nid("brainpoolP384r1");
		IEEE1609dot2BaseTypes::EccP384CurvePoint ec_point = v_key.ecdsaBrainpoolP384r1();

		if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP384CurvePoint::ALT_compressed__y__0)) {
			if (!LoadCompressedKey(nid, ec_point.compressed__y__0(), 0))   {
				ERROR_STREAMC << "cannot load Y0 compressed key" << std::endl;
				return false;
			}
		}
		else if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP384CurvePoint::ALT_compressed__y__1)) {
			if (!LoadCompressedKey(nid, ec_point.compressed__y__1(), 1))   {
				ERROR_STREAMC << "cannot load Y1 compressed key" << std::endl;
				return false;
			}
		}
		else if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP384CurvePoint::ALT_uncompressedP384)) {
			x = ec_point.uncompressedP384().x();
			y = ec_point.uncompressedP384().y();
		}
		else {
			ERROR_STREAMC << "EC point type '" << ec_point.get_selection() << "' not supported" << std::endl;
			return false;
		}
	}
	else {
		ERROR_STREAMC << "EC curve '" << v_key.get_selection() << "' not supported" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPublicKey::LoadEncryptionKeyFromCertificate(IEEE1609dot2::CertificateBase &in_cert)
{
	DEBUGC_STREAM_CALLED;
	
	if (!in_cert.is_present())   {
		ERROR_STREAMC << "invalid argument" << std::endl;
		return false;
	}

	IEEE1609dot2BaseTypes::PublicEncryptionKey e_key = in_cert.toBeSigned().encryptionKey();
	if (!e_key.is_present())   {
		ERROR_STREAMC << "no public encryption key" << std::endl;
		return false;
	}

    	if (e_key.publicKey().ischosen(IEEE1609dot2BaseTypes::BasePublicEncryptionKey::ALT_eciesNistP256)) {
		nid = OpenSSL_txt2nid("prime256v1");
		IEEE1609dot2BaseTypes::EccP256CurvePoint ec_point = e_key.publicKey().eciesNistP256();

      		if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__0)) {
			if (!LoadCompressedKey(nid, ec_point.compressed__y__0(), 0))   {
				ERROR_STREAMC << "cannot load Y0 compressed key" << std::endl;
				return false;
			}
		}
		else if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__1)) {
			if (!LoadCompressedKey(nid, ec_point.compressed__y__1(), 1))   {
				ERROR_STREAMC << "cannot load Y1 compressed key" << std::endl;
				return false;
			}
		}
		else if (e_key.publicKey().eciesNistP256().ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_uncompressedP256)) {
			x = ec_point.uncompressedP256().x();
			y = ec_point.uncompressedP256().y();
		}
		else   {
			ERROR_STREAMC << "not supported EC point type '" << ec_point.get_selection() << "'" << std::endl;
			return false;
		}
	}
    	else if (e_key.publicKey().ischosen(IEEE1609dot2BaseTypes::BasePublicEncryptionKey::ALT_eciesBrainpoolP256r1)) {
		nid = OpenSSL_txt2nid("brainpoolP256r1");
		IEEE1609dot2BaseTypes::EccP256CurvePoint ec_point = e_key.publicKey().eciesBrainpoolP256r1();

      		if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__0)) {
			if (!LoadCompressedKey(nid, ec_point.compressed__y__0(), 0))   {
				ERROR_STREAMC << "cannot load Y0 compressed key" << std::endl;
				return false;
			}
		}
		else if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__1)) {
			if (!LoadCompressedKey(nid, ec_point.compressed__y__1(), 1))   {
				ERROR_STREAMC << "cannot load Y1 compressed key" << std::endl;
				return false;
			}
		}
		else if (ec_point.ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_uncompressedP256)) {
			x = ec_point.uncompressedP256().x();
			y = ec_point.uncompressedP256().y();
		}
		else   {
			ERROR_STREAMC << "not supported EC point type '" << ec_point.get_selection() << "'" << std::endl;
			return false;
		}
	}
	else   {
		ERROR_STREAMC << "not supported EC curve '" << e_key.publicKey().get_selection() << "'" << std::endl;
		return false;
	}  
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPublicKey::GetXY(OCTETSTRING &_x, OCTETSTRING &_y)
{
	DEBUGC_STREAM_CALLED;

	if (x.is_present() && y.is_present() && x.lengthof() > 0 && y.lengthof() > 0)   {
		_x = x;
		_y = y;
		DEBUGC_STREAM_RETURNS_OK;
		return true;
	}

	ERROR_STREAMC << "failed " << std::endl;
	return false;
}


bool
ItsPkiEtsi::ItsPkiPublicKey::GetCompressed(OCTETSTRING &ret)
{
	DEBUGC_STREAM_CALLED;

	if (!comp_key.is_present() || comp_key.lengthof() <= 0)   {
		ERROR_STREAMC << "failed " << std::endl;
		return false;
	}

	ret = comp_key;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiRecipient::GetCertHash(OCTETSTRING &r_hash)
{
	DEBUGC_STREAM_CALLED;
	
	if (!cert_hash.is_present() || cert_hash.lengthof() == 0)   {
		ERROR_STREAMC << "failed " << std::endl;
		return false;
	}

	r_hash = cert_hash;
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}

	
bool
ItsPkiEtsi::ItsPkiRecipient::GetHashedID8(OCTETSTRING &ret)
{
	DEBUGC_STREAM_CALLED;
	
	if (!hashed_id8.is_present() || hashed_id8.lengthof() == 0)
		return false;

	ret = hashed_id8;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}

	
bool
ItsPkiEtsi::ItsPkiRecipient::ParseCert(IEEE1609dot2::CertificateBase &in_cert)
{
	DEBUGC_STREAM_CALLED;

	if (!in_cert.is_present())   {
		ERROR_STREAMC << "invalid argument" << std::endl;
		return false;
	}

        if (!in_cert.toBeSigned().encryptionKey().is_present())   {
		ERROR_STREAMC << "encryptionKey not present" << std::endl;
		return false;
	}

	cert = in_cert;
        if (!encEtsiTs103097Certificate(cert, cert_blob))    {
                ERROR_STREAMC << "cannot encode EtsiTs103097Certificate\n";
                return false;
        }
	dump_ttcn_object(cert_blob, "reencoded recipient certificate blob: ");

	if (!v_pub_key.LoadVerificationKeyFromCertificate(cert))   {
		ERROR_STREAMC << "cannot load VerificationKey" << std::endl;
		return false;
	}

	if (!e_pub_key.LoadEncryptionKeyFromCertificate(cert))   {
		ERROR_STREAMC << "cannot load EncryptionKey" << std::endl;
		return false;
	}

	int nid = v_pub_key.GetNID();
	if (nid == NID_X9_62_prime256v1 || nid == NID_brainpoolP256r1)   {
		if (!hash_256(cert_blob, cert_hash))   {
			ERROR_STREAMC << "failed to get certificate's hash256" << std::endl;
			return false;
		}
	}
        else if (nid == NID_brainpoolP384r1)   {
		if (!hash_384(cert_blob, cert_hash))   {
			ERROR_STREAMC << "failed to get certificate's hash384" << std::endl;
			return false;
		}
	}
	else   {
		ERROR_STREAMC << "Invalid verification key NID: " << nid << std::endl;
		return false;
	}
	hashed_id8 = OCTETSTRING(8, ((const unsigned char *)cert_hash + cert_hash.lengthof() - 8));
	dump_ttcn_object(hashed_id8, "#### HashedID8: ");

	if (cert.issuer().ischosen(IEEE1609dot2::IssuerIdentifier::ALT_sha256AndDigest)) {
		issuer_id8 = cert.issuer().sha256AndDigest();
	}
	else if (cert.issuer().ischosen(IEEE1609dot2::IssuerIdentifier::ALT_sha384AndDigest)) {
		issuer_id8 = cert.issuer().sha384AndDigest();
	}
	else if (cert.issuer().ischosen(IEEE1609dot2::IssuerIdentifier::ALT_self__)) {
		issuer_id8 = OCTETSTRING(8, ((const unsigned char *)cert_hash + cert_hash.lengthof() - 8));
	}
	else {
		ERROR_STREAMC << "unsupported issuer type '" << cert.issuer().get_selection() << "'" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


ItsPkiEtsi::~ItsPkiEtsi()
{
	OpenSSL_cleanup();
}


bool
ItsPkiEtsi::setRecipient(OCTETSTRING &cert_blob, void *e_prvkey)
{
	DEBUGC_STREAM_CALLED;

	dump_ttcn_object(cert_blob, "recipient certificate blob: ");
	IEEE1609dot2::CertificateBase cert = decEtsiTs103097Certificate(cert_blob);
	dump_ttcn_object(cert, "recipient certificate: ");

	if (!recipient.ParseCert(cert))   {
		ERROR_STREAMC << "cannot parse recipient certificate" << std::endl;
		return false;
	}
	if (e_prvkey)
		recipient.SetPrivateKey(e_prvkey);
	ready = true;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::setDecryptContext(void *prvkey, void *pubkey)
{
	DEBUGC_STREAM_CALLED;

	DEBUGC_STREAM << "PrvKey: " << prvkey << " PubKey: " << pubkey << std::endl;
	recipient.SetPrivateKey(prvkey);
	recipient.SetSenderPublicKey(pubkey);

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::setDecryptContextWithSKey(OCTETSTRING &skey_id)
{
	DEBUGC_STREAM_CALLED;

	if (!enc_key.checkDecryptContext(skey_id))   {
		ERROR_STREAMC << "failed to set decryption context" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::setDecryptContextWithSKey(OCTETSTRING &skey_id, OCTETSTRING &aes_key, OCTETSTRING &tag)
{
	enc_key.setup_skey(aes_key, tag);
	return setDecryptContextWithSKey(skey_id);
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::setup(int in_nid, const char *prvkey_str)
{
	DEBUGC_STREAM_CALLED;
	DEBUGC_STREAM << "nid:" << in_nid << ", prvkey" << std::endl;

	if (!ECKey_KeyComponentsFromString(in_nid, prvkey_str, pubkey.x, pubkey.y, pubkey.comp_key, pubkey.comp_key_mode))   {
		ERROR_STREAMC << "cannot parse private EC key" << std::endl;
		return false;
	}
	pubkey.nid = in_nid;
	prvkey_oct = str2oct(prvkey_str);

	dump_ttcn_object(prvkey_oct, "PrvKey raw: ");
	dump_ttcn_object(pubkey.x, "PrvKey X: ");
	dump_ttcn_object(pubkey.y, "PrvKey Y: ");
	dump_ttcn_object(pubkey.comp_key, "PrvKey CompPubKey: ");
	dump_ttcn_object(pubkey.comp_key_mode, "PrvKey CompPubKeyMode: ");
	DEBUGC_STREAM << "PrvKey NID:" <<  pubkey.nid << std::endl;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::setup(void *in_key, OCTETSTRING &in_enc_skey)
{
	DEBUGC_STREAM_CALLED;

	if (EC_KEY_check_key((EC_KEY *)in_key) == 0)    {
		ERROR_STREAMC << "not valid EC key" << std::endl;
		return false;
	}
	ec_key = in_key;

	enc_skey = in_enc_skey;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::generate(int in_nid)
{
	DEBUGC_STREAM_CALLED;

	if (ec_key != NULL)
		ECKey_Free(ec_key);
	if (!ECKey_NewKey(in_nid, (void **)(&ec_key), prvkey_oct, pubkey.x, pubkey.y, pubkey.comp_key, pubkey.comp_key_mode))   {
		ERROR_STREAMC << "failed to generate new EC key" << std::endl;
		return false;
	}
	pubkey.nid = in_nid;

	dump_ttcn_object(prvkey_oct, "PrvKey raw: ");
	dump_ttcn_object(pubkey.x, "PrvKey X:");
	dump_ttcn_object(pubkey.y, "PrvKey Y:");
	dump_ttcn_object(pubkey.comp_key, "PrvKey CompPubKey:");
	dump_ttcn_object(pubkey.comp_key_mode, "PrvKey CompPubKeyMode:");
	DEBUGC_STREAM << "PrvKey NID:" <<  pubkey.nid << std::endl;

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::checkDecryptContext(OCTETSTRING &skey_id8)
{
	DEBUGC_STREAM_CALLED;
	
	if (!skey_id8.is_bound() || !aes_skey.is_bound())   {
		ERROR_STREAMC << "invalid Decrypt context" << std::endl;
		return false;
	}

	IEEE1609dot2BaseTypes::SymmetricEncryptionKey skey_type;
        skey_type.aes128Ccm() = aes_skey;

	OCTETSTRING skey_encoded;
	if (!encSymmetricEncryptionKey(skey_type, skey_encoded))   {
		ERROR_STREAMC << "failed to encode IEEE1609dot2BaseTypes::SymmetricEncryptionKey" << std::endl;
		return false;
	}

	OCTETSTRING aes_key_id8;
	if (!hash_256_id8(skey_encoded, aes_key_id8))   {
		ERROR_STREAMC << "cannot get sha256 hashed ID8" << std::endl;
		return false;
	}

	if (aes_key_id8 != skey_id8)   {
		ERROR_STREAMC << "invalid AES key" << std::endl;
		return false;
	}

	if (!tag.is_bound() || tag.lengthof() == 0)   {
		ERROR_STREAMC << "no TAG in decryption context" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::decryptAes128ccm(IEEE1609dot2::AesCcmCiphertext &aes128ccm, OCTETSTRING &ret)
{
	DEBUGC_STREAM_CALLED;

	if (!aes128ccm.is_bound())   {
		ERROR_STREAMC << "invalid argument" << std::endl;
		return false;
	}

        int tag_len = tag.lengthof();
	OCTETSTRING tag(tag_len, (const unsigned char *)aes128ccm.ccmCiphertext() + aes128ccm.ccmCiphertext().lengthof() - tag_len);
	
	OCTETSTRING ctext(aes128ccm.ccmCiphertext().lengthof() - tag_len, (const unsigned char *)aes128ccm.ccmCiphertext());

	dump_ttcn_object(aes_skey, "AES SKey: ");
	if (!OpenSSL_Decrypt_aes128ccm(ctext, tag, aes128ccm.nonce(), aes_skey, ret))   {
		ERROR_STREAMC << "AES-128-CCM decrypt error" << std::endl;
		return false;
	}
	dump_ttcn_object(ret, "Decrypted payload: ");
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::derivate(const OCTETSTRING &x, const OCTETSTRING &y, const OCTETSTRING &salt)
{
	DEBUGC_STREAM_CALLED;

	if (!IsValid())   {
		ERROR_STREAMC << "private key data are not valid" << std::endl;
		return false;
	}
	
	if (!ECKey_DerivateSKey_aes128ccm(ec_key, x, y, salt, aes_skey, enc_skey, tag))   {
		ERROR_STREAMC << "Cannot derivate SKey" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::GetP256CurvePoint(IEEE1609dot2BaseTypes::EccP256CurvePoint &ret)
{
	DEBUGC_STREAM_CALLED;

	if (pubkey.GetCompressedMode() == 0)   {
		if (!pubkey.GetCompressed(ret.compressed__y__0()))   {
			ERROR_STREAMC << "cannot get compressed Y0 component" << std::endl;
			return false;
		}
	}
	else if (pubkey.GetCompressedMode() == 1)   {
		if (!pubkey.GetCompressed(ret.compressed__y__1()))   {
			ERROR_STREAMC << "cannot get compressed Y1 component" << std::endl;
			return false;
		}
	}
	else   {
		if (!pubkey.GetXY(ret.uncompressedP256().x(), ret.uncompressedP256().y()))   {
			ERROR_STREAMC << "cannot get uncompressed components" << std::endl;
			return false;
		}
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::GetEciesP256EncryptedKey(IEEE1609dot2BaseTypes::EciesP256EncryptedKey &ret)
{
	DEBUGC_STREAM_CALLED;

	IEEE1609dot2BaseTypes::EccP256CurvePoint eccP256CurvePoint;
	if (!GetP256CurvePoint(eccP256CurvePoint))   {
		ERROR_STREAMC << "cannot get IEEE1609dot2BaseTypes::EccP256CurvePoint" << std::endl;
		return false;
	}

	if (!enc_skey.is_present())   {
		ERROR_STREAMC << "invalid context: enc_skey is missing" << std::endl;
		return false;
	}

	if (!tag.is_present())   {
		ERROR_STREAMC << "invalid context: tag is missing" << std::endl;
		return false;
	}

	ret = IEEE1609dot2BaseTypes::EciesP256EncryptedKey(eccP256CurvePoint, enc_skey, tag);
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::GetEncryptedDataEncryptionKey(IEEE1609dot2::EncryptedDataEncryptionKey &ret)
{
	DEBUGC_STREAM_CALLED;

	IEEE1609dot2BaseTypes::EciesP256EncryptedKey ecies_key;
	if (!GetEciesP256EncryptedKey(ecies_key))   {
		ERROR_STREAMC << "failed to get IEEE1609dot2BaseTypes::EciesP256EncryptedKey" << std::endl;
		return false;
	}
	
	switch (pubkey.nid)  {
	case NID_X9_62_prime256v1:
		ret.eciesNistP256() = ecies_key;
		break;	
	case NID_brainpoolP256r1:
		ret.eciesBrainpoolP256r1() = ecies_key;
		break;
	default:
		ERROR_STREAMC << "EC curve '" << pubkey.nid << "' do not supported" << std::endl;
		return false;
	}

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::encrypt(const OCTETSTRING &msg, OCTETSTRING &nonce, OCTETSTRING &enc_msg)
{
	DEBUGC_STREAM_CALLED;

	nonce = random_OCTETSTRING(Ieee1609Dot2Data_AesCcmCiphertext_NonceLength);
	switch (enc_algorithm) {
	case NID_aes_128_ccm:
		if (!OpenSSL_Encrypt_aes128ccm(msg, nonce, aes_skey, tag, enc_msg))   {
			ERROR_STREAMC << "OpenSSL encrypt AES 128 CCM failed" << std::endl;
			return false;
		}
		break;
	default:
		ERROR_STREAMC << "encryption algorithm '" << enc_algorithm << "' do not supported" << std::endl;
		return false;
	}

	dump_ttcn_object(aes_skey, "Encrypt(): AES SKey: ");
	dump_ttcn_object(nonce, "Encrypt(): Nonce: ");
	dump_ttcn_object(tag, "Encrypt(): Tag: ");
	OCTETSTRING _msg = msg;
	dump_ttcn_object(_msg, "Encrypt(): Message: ");
	dump_ttcn_object(enc_msg, "Encrypt(): Encrypted Message: ");
	
	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::encrypt(const OCTETSTRING &msg, IEEE1609dot2::AesCcmCiphertext &cipher_txt)
{
	DEBUGC_STREAM_CALLED;

	OCTETSTRING nonce, enc_msg;
	if (!this->encrypt(msg, nonce, enc_msg))   {
		ERROR_STREAMC << "encrypt failed" << std::endl;
		return false;
	}

	cipher_txt = IEEE1609dot2::AesCcmCiphertext(nonce, enc_msg + tag); // Add tag at the end of the ciphered text
	dump_ttcn_object(cipher_txt, "AesCcmCiphertext: ");

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::ItsPkiPrivateKey::encrypt(const OCTETSTRING &msg, IEEE1609dot2::SymmetricCiphertext &sym_cipher_txt)
{
	DEBUGC_STREAM_CALLED;

	IEEE1609dot2::AesCcmCiphertext aes_128_ccm;
	if (!this->encrypt(msg, aes_128_ccm))   {
		ERROR_STREAMC << "encrypt message failed" << std::endl;
		return false;
	}
	dump_ttcn_object(aes_128_ccm, "Encrypted message: ");

	sym_cipher_txt.aes128ccm() = aes_128_ccm;
	dump_ttcn_object(sym_cipher_txt, "SymmetricCiphertext: ");

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::EncryptPayload(OCTETSTRING &tbe, EtsiTs103097Module::EtsiTs103097Data__Encrypted__My &ret)
{
	DEBUGC_STREAM_CALLED;
	
	if (!ready)   {
                ERROR_STREAMC << "error: etsi service is not properly initialized" << std::endl;
		return false;
	}

#if 0
	if (!enc_key.setup(GetRecipientEncryptionNID(), "BCF939F56A94FC275CD0AE6BD2165D62BA58113EA0B22C3FE14956470C9B503D"))
		return false;
#else
	if (!enc_key.generate(GetRecipientEncryptionNID()))   {
                ERROR_STREAMC << "failed to generate encryption key" << std::endl;
		return false;
	}

#endif

	OCTETSTRING r_enc_pubkey_x, r_enc_pubkey_y;
	if (!recipient.GetEncryptionXY(r_enc_pubkey_x, r_enc_pubkey_y))   {
                ERROR_STREAMC << "failed to get recipient encryption XY components" << std::endl;
		return false;
	}

	OCTETSTRING r_cert_hash;
	if (!recipient.GetCertHash(r_cert_hash))   {
                ERROR_STREAMC << "failed to get recipient certificate's hash" << std::endl;
		return false;
	}

	dump_ttcn_object(r_enc_pubkey_x, "Recipient pubkey X: ");
	dump_ttcn_object(r_enc_pubkey_y, "Recipient pubkey Y: ");
	dump_ttcn_object(r_cert_hash, "Recipient Cert Hash: ");
	if (!enc_key.derivate(r_enc_pubkey_x, r_enc_pubkey_y, r_cert_hash))   {
                ERROR_STREAMC << "derivate failed" << std::endl;
		return false;
	}

	IEEE1609dot2::EncryptedDataEncryptionKey enc_data_key;
	if (!enc_key.GetEncryptedDataEncryptionKey(enc_data_key))   {
                ERROR_STREAMC << "cannot get IEEE1609dot2::EncryptedDataEncryptionKey" << std::endl;
		return false;
	}
	dump_ttcn_object(enc_data_key, "EncryptedDataEncryptionKey: ");

	//     cipher_text := { aes128ccm := { nonce := ''O, ccmCiphertext := ''O } }
	IEEE1609dot2::SymmetricCiphertext cipher_text;
	if (!enc_key.encrypt(tbe, cipher_text))   {
                ERROR_STREAMC << "encrypt cipher text failed" << std::endl;
		return false;
	}
	dump_ttcn_object(cipher_text, "Encrypted payload: ");

	OCTETSTRING cipher_txt_oct;
	if (!encSymmetricCiphertext(cipher_text, cipher_txt_oct))   {
                ERROR_STREAMC << "encode SymmetricCiphertext failed" << std::endl;
		return false;
	}
	dump_ttcn_object(cipher_txt_oct, "Encoded Encrypted payload: ");

	OCTETSTRING recipient_id;
	if (!recipient.GetHashedID8(recipient_id))   {
                ERROR_STREAMC << "cannot get recipiet hashed ID8" << std::endl;
		return false;
	}
	dump_ttcn_object(recipient_id, "Recipient ID: ");

	//  certRecipInfo := {
	//    recipientId := ''O,
	//    encKey := { eciesNistP256 := { v := { compressed_y_0 := ''O }, c := ''O, t := ''O } } 
	//  } 
	IEEE1609dot2::PKRecipientInfo cert_recipient_info(recipient_id, enc_data_key);
	IEEE1609dot2::RecipientInfo recipient_info;
	recipient_info.certRecipInfo() = cert_recipient_info;
	IEEE1609dot2::SequenceOfRecipientInfo recipients;
	recipients[0] = recipient_info;

	// encryptedData := {
	//     recipients := { { certRecipInfo := { recipientId := ''O, encKey := { eciesNistP256 := { v := { compressed_y_0 := ''O }, c := ''O, t := ''O } } } } },
	//     ciphertext := { aes128ccm := { nonce := ''O, ccmCiphertext := ''O } }
	// }
	IEEE1609dot2::EncryptedData encrypted_data(recipients, cipher_text);
	dump_ttcn_object(encrypted_data, "EncryptedData:  ");
  
	IEEE1609dot2::Ieee1609Dot2Content ieee_dot2_content;
 	ieee_dot2_content.encryptedData() = encrypted_data;

	// { protocolVersion := 3,
	//   content := { encryptedData := {
	//      recipients := { { certRecipInfo := { recipientId := ''O, encKey := { eciesNistP256 := { v := { compressed_y_0 := ''O }, c := ''O, t := ''O } } } } },
	//      ciphertext := { aes128ccm := { nonce := ''O, ccmCiphertext := ''O } } } } }
	ret = IEEE1609dot2::Ieee1609Dot2Data(Ieee1609Dot2Data_ProtocolVersion, ieee_dot2_content);
	dump_ttcn_object(ret, "EncryptedData Payload: ");

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}


bool
ItsPkiEtsi::DecryptPayload(OCTETSTRING &in_raw, OCTETSTRING &payload)
{
	DEBUGC_STREAM_CALLED;
	
	if (!ready)   {
                ERROR_STREAMC << "error: etsi service is not properly initialized" << std::endl;
		return false;
	}

        // { protocolVersion := 3, content := { encryptedData := { recipients := { { pskRecipInfo := ''O } }, ciphertext := { aes128ccm := { nonce := ''O, ccmCiphertext := ''O } } } } }
        EtsiTs103097Module::EtsiTs103097Data__Encrypted__My data_encrypted;
	try   {
		OCTETSTRING _in_raw = in_raw;
        	EtsiTs103097Module::EtsiTs103097Data__Encrypted__My_decoder(_in_raw, data_encrypted, "OER");
	}
	catch (const TC_Error& tc_error) {
		bool ascii = true;
		for (int ii = 0; ii < 200 && ii < in_raw.lengthof(); ii++)   {
			char ch = *((char *)(const unsigned char *)in_raw + ii);
			if (!isascii((ch)))   {
				ascii = false;
				break;
			}
		}

		ERROR_STREAMC << "cannot decode payload: " << (ascii ? (char *)((const unsigned char *)in_raw) : oct2str(in_raw)) << std::endl;
		return false;
	}

	return DecryptPayload(data_encrypted, payload);
}


bool
ItsPkiEtsi::DecryptPayload(EtsiTs103097Module::EtsiTs103097Data__Encrypted__My &data_encrypted, OCTETSTRING &payload)
{
	DEBUGC_STREAM_CALLED;
	
        // { protocolVersion := 3, content := { encryptedData := { recipients := { { pskRecipInfo := ''O } }, ciphertext := { aes128ccm := { nonce := ''O, ccmCiphertext := ''O } } } } }
	if (!ready)   {
                ERROR_STREAMC << "error: etsi service is not properly initialized" << std::endl;
		return false;
	}

        if (!data_encrypted.is_bound()) {
                ERROR_STREAMC << "cannot decode response encrypted data" << std::endl;
                return false;
        }
        dump_ttcn_object(data_encrypted, "EtsiTs103097Module::EtsiTs103097Data__Encrypted__My response: ");

        if (!data_encrypted.content().ischosen(IEEE1609dot2::Ieee1609Dot2Content::ALT_encryptedData))   {
                ERROR_STREAMC << "'"<< data_encrypted.content().get_selection() << "' content type instead of expected 'ALT_encryptedData'" << std::endl;
                return false;
        }

        IEEE1609dot2::RecipientInfo rinfo = data_encrypted.content().encryptedData().recipients()[0];
	if (rinfo.ischosen(IEEE1609dot2::RecipientInfo::ALT_certRecipInfo))   {
		if (recipient.GetPrivateKey() == NULL)   {
                	ERROR_STREAMC << "No recipient private key" << std::endl;
                	return false;
		}

		OCTETSTRING recipient_id;
		if (!this->recipient.GetHashedID8(recipient_id))   {
                	ERROR_STREAMC << "Cannot get HashedID " << std::endl;
                	return false;
		}

		if (recipient_id != rinfo.certRecipInfo().recipientId())   {
			ERROR_STREAMC << "No recipient with id '" << oct2str(recipient_id) << std::endl;
			return false;
		}
		
		int nid;
		IEEE1609dot2BaseTypes::EciesP256EncryptedKey ecies_key;
		if (rinfo.certRecipInfo().encKey().ischosen(IEEE1609dot2::EncryptedDataEncryptionKey::ALT_eciesNistP256)) {
			ecies_key = rinfo.certRecipInfo().encKey().eciesNistP256();
			nid = NID_X9_62_prime256v1;
		}
				                
		else if (rinfo.certRecipInfo().encKey().ischosen(IEEE1609dot2::EncryptedDataEncryptionKey::ALT_eciesBrainpoolP256r1)) {
			ecies_key = rinfo.certRecipInfo().encKey().eciesBrainpoolP256r1();
			nid = NID_brainpoolP256r1;
		}
		else {
			ERROR_STREAMC << "Unsupported type of ECIES encrypted key " << std::endl;
			return false;
		}

        	OCTETSTRING comp, x, y;
        	int y_bit = -1;
        	if (ecies_key.v().ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_uncompressedP256)) {
                	x = ecies_key.v().uncompressedP256().x();
                	y = ecies_key.v().uncompressedP256().y();
        	}
        	else if (ecies_key.v().ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__0))   {
                	comp = ecies_key.v().compressed__y__0();
                	y_bit = 0;

                	if (!ECKey_DecompressPublicKey(nid, comp, 0, x, y))   {
                        	ERROR_STREAMC << "Cannot decompress EC PublicKey" << std::endl;
                        	return false;
                	}
        	}
        	else if (ecies_key.v().ischosen(IEEE1609dot2BaseTypes::EccP256CurvePoint::ALT_compressed__y__1))   {
                	comp = ecies_key.v().compressed__y__1();
                	y_bit = 1;
                	if (!ECKey_DecompressPublicKey(nid, comp, 1, x, y))   {
                        	ERROR_STREAMC << "Cannot decompress EC PublicKey" << std::endl;
                        	return false;
                	}
        	}
        	else   {
                	ERROR_STREAMC << "Unsupported EC key form" << std::endl;
                	return false;
        	}
        	dump_ttcn_object(x, "Sender X: ");
        	dump_ttcn_object(y, "Sender Y: ");

		OCTETSTRING salt;
		if (!recipient.GetCertHash(salt))   {
                	ERROR_STREAMC << "Failed to get certificate hash " << std::endl;
                	return false;
		}

		enc_key.setup(recipient.GetPrivateKey(), ecies_key.c());
		if (!enc_key.derivate(x, y, salt))   {
                	ERROR_STREAMC << "Cannot derivate " << std::endl;
                	return false;
		}
	}
	else if (rinfo.ischosen(IEEE1609dot2::RecipientInfo::ALT_pskRecipInfo))  {
        	OCTETSTRING skey_id = rinfo.pskRecipInfo();
		if (!setDecryptContextWithSKey(skey_id))   {
                	ERROR_STREAMC << "cannot setup decrypt context" << std::endl;
                	return false;
        	}
	}
	else   {
                ERROR_STREAMC << "'" << rinfo.get_selection() << "' recipient type, instead of expected 'ALT_pskRecipInfo'" << std::endl;
                return false;
        }

        IEEE1609dot2::AesCcmCiphertext aes128ccm = data_encrypted.content().encryptedData().ciphertext().aes128ccm();
        dump_ttcn_object(aes128ccm, "IEEE1609dot2::AesCcmCiphertext: ");

        if (!enc_key.decryptAes128ccm(aes128ccm, payload))   {
                ERROR_STREAMC << "decrypt with Aes128CCM failed" << std::endl;
                return false;
        }

	DEBUGC_STREAM_RETURNS_OK;
	return true;
}
