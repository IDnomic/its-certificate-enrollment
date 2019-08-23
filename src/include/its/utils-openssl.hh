#ifndef UTILS_OPENSSL_HH
#define UTILS_OPENSSL_HH

#include <string>
#include <iostream>
#include <memory>

#include "TTCN3.hh"

bool hash_256(OCTETSTRING &, OCTETSTRING &);
bool hash_256_id8(OCTETSTRING &, OCTETSTRING &);
bool hash_384(OCTETSTRING &, OCTETSTRING &);
bool hash_384_id8(OCTETSTRING &, OCTETSTRING &);
bool hmac_sha256(OCTETSTRING &, OCTETSTRING &, OCTETSTRING &);
OCTETSTRING random_OCTETSTRING(size_t);
bool kdf2_sha256(const OCTETSTRING &, const OCTETSTRING &, const int, OCTETSTRING &);
void *ECKey_ReadPrivateKey(const char *);
void *ECKey_ReadPrivateKeyB64(const char *);
void *ECKey_GeneratePrivateKey(void);
bool ECKey_PrivateKeyToFile(void *, const char *);
bool ECKey_PublicKeyToMemory(const void *, unsigned char **, size_t *);
bool ECKey_PublicKeyHashedID(void *, OCTETSTRING &);
bool ECKey_GetPublicKeyComponents(void *, int &, OCTETSTRING &, OCTETSTRING &);
bool ECKey_PublicKeyFromComponents(int nid, OCTETSTRING &x, OCTETSTRING &y, OCTETSTRING &comp, int y_bit, void **ret_key);
bool ECKey_DecompressPublicKey(int, OCTETSTRING &, int, OCTETSTRING &, OCTETSTRING &);
bool ECKey_KeyComponentsFromString(int, const char *, OCTETSTRING &, OCTETSTRING &, OCTETSTRING &, INTEGER &);
bool ECKey_DerivateSKey_aes128ccm(void *, const OCTETSTRING &, const OCTETSTRING &, const OCTETSTRING &, OCTETSTRING &, OCTETSTRING &, OCTETSTRING &);
bool ECKey_NewKey(int, void **, OCTETSTRING &, OCTETSTRING &, OCTETSTRING &, OCTETSTRING &, INTEGER &);
int  ECKey_GetNid(void *);
void ECKey_Free(void *);
bool IEEE1609dot2_SignWithSha256(OCTETSTRING &, OCTETSTRING &, void *, OCTETSTRING &, OCTETSTRING &);
bool IEEE1609dot2_SignWithSha384(OCTETSTRING &, OCTETSTRING &, void *, OCTETSTRING &, OCTETSTRING &);
bool OpenSSL_SHA256_HashedID(OCTETSTRING &, OCTETSTRING &);
bool OpenSSL_SHA384_HashedID(OCTETSTRING &, OCTETSTRING &);
bool OpenSSL_Encrypt_aes128ccm(const OCTETSTRING &, OCTETSTRING &, OCTETSTRING &, OCTETSTRING &, OCTETSTRING &);
bool OpenSSL_Decrypt_aes128ccm(const OCTETSTRING &, OCTETSTRING &, OCTETSTRING &, OCTETSTRING &, OCTETSTRING &);
int  OpenSSL_txt2nid(const char *);
void OpenSSL_setup(void);
void OpenSSL_cleanup(void);

bool OpenSSL_Verify(void *key, OCTETSTRING &r, OCTETSTRING &s, OCTETSTRING &data);
bool IEEE1609dot2_VerifyWithSha256(void *key, OCTETSTRING &r, OCTETSTRING &s, OCTETSTRING &data, OCTETSTRING &signer);
bool IEEE1609dot2_VerifyWithSha384(void *key, OCTETSTRING &r, OCTETSTRING &s, OCTETSTRING &data, OCTETSTRING &signer);

#if 0
bool myECKey_DerivateSKey_aes128ccm(void *in_eckey,
		const OCTETSTRING &x, const OCTETSTRING &y,
		const OCTETSTRING &enc_sym_key, const OCTETSTRING &expected_nonce,
		const OCTETSTRING &authentication_vector, const OCTETSTRING &salt);
#endif
#endif // UTILS_OPENSSL_HH
