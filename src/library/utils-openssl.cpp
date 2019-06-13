// https://gist.github.com/a2e0040d301bf4b8ef8101c0b1e3f1d5.git
#include <string>
#include <iostream>
#include <memory>
#include <cstdio>

#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include "its/pki-its-debug.hh"
#include "its/utils-ttcn.hh"
#include "its/utils-openssl.hh"

bool
hash_256(OCTETSTRING &data, OCTETSTRING &ret)
{
	unsigned char buff[SHA256_DIGEST_LENGTH] = {0};
        unsigned char *sha = &buff[0];

        if (SHA256((const unsigned char *)data, data.lengthof(), sha) != sha)
		return false;
	
	ret = OCTETSTRING(SHA256_DIGEST_LENGTH, sha);
	return true;
}


bool
hash_256_id8(OCTETSTRING &data, OCTETSTRING &ret)
{
	OCTETSTRING hash;
	if (!hash_256(data, hash))
		return false;
	ret = substr(hash, hash.lengthof() - 8, 8);
	return true;
}


bool
hash_384(OCTETSTRING &data, OCTETSTRING &ret)
{
	unsigned char buff[SHA384_DIGEST_LENGTH] = {0};
        unsigned char *sha = &buff[0];

        if (SHA384((const unsigned char *)data, data.lengthof(), sha) != sha)
		return false;
	
	ret = OCTETSTRING(SHA384_DIGEST_LENGTH, sha);
	return true;
}


bool
hash_384_id8(OCTETSTRING &data, OCTETSTRING &ret)
{
	OCTETSTRING hash;
	if (!hash_384(data, hash))
		return false;
	ret = substr(hash, hash.lengthof() - 8, 8);
	return true;
}


OCTETSTRING
random_OCTETSTRING(size_t size)
{
	BIGNUM* r = BN_new();	
	BN_pseudo_rand(r, size * 8, 0, 0);
	unsigned char *buff = (unsigned char *)malloc(BN_num_bytes(r));
	BN_bn2bin(r, buff);
	
	OCTETSTRING ret = OCTETSTRING(size, buff);
	
	BN_free(r);
	free(buff);

	return ret;
}


bool
hmac_sha256(OCTETSTRING &data, OCTETSTRING &key, OCTETSTRING &ret)
{
	if (!data.is_bound() || data.lengthof() == 0)
		return false;
	if (!key.is_bound() || key.lengthof() == 0)
		return false;
	
	HMAC_CTX *ctx = HMAC_CTX_new();
	HMAC_CTX_reset(ctx);

	ret = int2oct(0, EVP_MAX_MD_SIZE);
	HMAC_Init_ex(ctx, (const void*)((const unsigned char *)key), key.lengthof(), EVP_sha256(), NULL);
  	HMAC_Update(ctx, (const unsigned char *)data, data.lengthof());
	
	unsigned int len = ret.lengthof();
	HMAC_Final(ctx, (unsigned char*)((const unsigned char *)ret), &len);
    	ret = OCTETSTRING(16, (const unsigned char *)ret);
	HMAC_CTX_free(ctx);	

	return true;
}


bool
kdf2_sha256(const OCTETSTRING &skey, const OCTETSTRING &salt, const int ret_len, OCTETSTRING &ret_digest)
{
        DEBUG_STREAM_CALLED;

        int num = (ret_len + SHA256_DIGEST_LENGTH - 1)/SHA256_DIGEST_LENGTH;
        ret_digest = OCTETSTRING(0, NULL);
        for (int ii = 1; ii < num + 1; ii++) {
                unsigned char sha256_buff[SHA256_DIGEST_LENGTH];
                OCTETSTRING hash_input = skey + int2oct(ii, 4) + salt;
                SHA256((const unsigned char *)hash_input, hash_input.lengthof(), sha256_buff);

                ret_digest += OCTETSTRING(SHA256_DIGEST_LENGTH, sha256_buff);
        }

        DEBUG_STREAM_RETURNS_OK;
        return true;
}


void *
ECKey_GeneratePrivateKey(void)
{
    EC_GROUP *group = NULL;
    EC_KEY *key = NULL;

    key = EC_KEY_new();
    if (!key)
        return NULL;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group)   {
        EC_KEY_free(key);
        return NULL;
    }

    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

    if (EC_KEY_set_group(key, group) == 0)   {
        EC_GROUP_free(group);
        EC_KEY_free(key);
        return NULL;
    }

    if (!EC_KEY_generate_key(key))   {
        EC_GROUP_free(group);
        EC_KEY_free(key);
        return NULL;
    }

    // EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);

    EC_GROUP_free(group);
    return key;
}


bool
ECKey_PrivateKeyToFile(void *key, const char *filename)
{
	bool result = false;

	if (EC_KEY_check_key((EC_KEY *)key) == 0) {
		ERROR_STREAM << "invalid EC key" << std::endl;
		return false;
	}

	BIO *bio = BIO_new(BIO_s_file()); 
	if (!BIO_write_filename(bio, (void *)filename))
    		goto done;

	if (!PEM_write_bio_ECPrivateKey(bio, (EC_KEY *)key, NULL, NULL, 0, NULL, NULL))
		goto done;

	BIO_flush(bio);

	result = true;
done:
	BIO_free(bio);
	return result;
}


bool
ECKey_PublicKeyToMemory(const void *key, unsigned char **out, size_t *out_len)
{
	BIO *mem = NULL, *b64 = NULL, *bio = NULL;
	unsigned char *mem_ptr = NULL;
	long mem_length = 0;
	int  ii;

	if (EC_KEY_check_key((EC_KEY *)key) == 0) {
		ERROR_STREAM << "invalid EC key" << std::endl;
		return false;
	}

	if ((out == NULL) || (out_len == NULL))
		return false;

	mem = BIO_new(BIO_s_mem());
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, mem);

	if (!i2d_EC_PUBKEY_bio(bio, (EC_KEY *)key))   {
		ERROR_STREAM << "Cannot get EC public key to memory" << std::endl;
        	return false;
    	}

	BIO_flush(bio);
	BIO_flush(b64);
	BIO_flush(mem);

	mem_length = BIO_get_mem_data(mem, &mem_ptr);
	if (!mem_ptr || !mem_length)
		return -1;

	*out = (unsigned char *)malloc(mem_length + 1);
	if (*out == NULL)   {
		ERROR_STREAM << "Cannot allocate memory for EC public key" << std::endl;
        	return false;
    	}
    	memcpy(*out, mem_ptr, mem_length);
    	*(*out + mem_length) = '\0';

    	for (ii=0; (ii < mem_length) && (*(*out + ii) != '\0'); ii++)
        	if (*(*out + ii) == '\n')
			memcpy(*out + ii, *out  + ii + 1, mem_length - ii);

	*out_len = strlen((char *)(*out));
	*(*out + *out_len) = '\0';

	BIO_free_all(bio);
	return true;
}


void *
ECKey_ReadPrivateKey(const char *filename)
{
	DEBUG_STREAM_CALLED;
	
	EC_KEY *key = NULL;

	BIO *bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename))
		key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);

	BIO_free(bio);
	return key;
}


void *
ECKey_ReadPrivateKeyB64(const char *b64)
{
	DEBUG_STREAM_CALLED;

	unsigned char buffer[4096];
	FILE *stream = fmemopen((void *)b64, strlen(b64), "r");
	BIO *bio64 = BIO_new(BIO_f_base64());
	BIO *bio = BIO_new_fp(stream, BIO_NOCLOSE);

	bio = BIO_push(bio64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	int len = BIO_read(bio, buffer, strlen(b64));
	BIO *mem = BIO_new_mem_buf(buffer, len);
	
	EC_KEY *key = d2i_ECPrivateKey_bio(mem, NULL);

	BIO_free(mem);
	BIO_free_all(bio);
	fclose(stream);

	return key;
}


bool
ECKey_PublicKeyHashedID(void *key, OCTETSTRING &ret)
{
    BIO *mem = NULL;
    unsigned char sha256_buff[SHA256_DIGEST_LENGTH];
    unsigned char *mem_ptr = NULL;
    long mem_length = 0;

    if (EC_KEY_check_key((EC_KEY *)key) == 0) {
	ERROR_STREAM << "invalid EC key" << std::endl;
	return false;
    }
    mem = BIO_new(BIO_s_mem());

    if (!i2d_EC_PUBKEY_bio(mem, (EC_KEY *)key))   {
	ERROR_STREAM << "Cannot get EC public key to memory" << std::endl;
        return false;
    }

    BIO_flush(mem);

    mem_length = BIO_get_mem_data(mem, &mem_ptr);
    if (!mem_ptr || !mem_length)
        return false;

    memset(sha256_buff, 0, sizeof(sha256_buff));
    SHA256(mem_ptr, mem_length, sha256_buff);
    ret = OCTETSTRING(8, sha256_buff + sizeof(sha256_buff) - 8);

    BIO_free_all(mem);
    return true;
}


bool
OpenSSL_Sign(const EVP_MD *evp_md, const unsigned char *data, int data_len, void *key, unsigned char **out, size_t *out_len)
{
	if (out == NULL || out_len == NULL)
		return false;

	if (EC_KEY_check_key((EC_KEY *)key) == 0) {
		ERROR_STREAM << "invalid EC key" << std::endl;
		return false;
	}

	EVP_PKEY *evp_pkey = EVP_PKEY_new();
	if (!evp_pkey)
		return false;

	EVP_PKEY_set1_EC_KEY(evp_pkey, (EC_KEY *)key);

	EVP_PKEY_CTX *evp_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
	if (!evp_pkey_ctx)
		return false;

	if (EVP_PKEY_sign_init(evp_pkey_ctx) <= 0)
		return false;
	if (evp_md != NULL)
		if (EVP_PKEY_CTX_set_signature_md(evp_pkey_ctx, evp_md) <= 0)
			return false;

	size_t siglen;
 	if (EVP_PKEY_sign(evp_pkey_ctx, NULL, &siglen, data, data_len) <= 0)
		return false;

	unsigned char *sig = (unsigned char *)OPENSSL_malloc(siglen);
	if (!sig)
		return false;

	if (EVP_PKEY_sign(evp_pkey_ctx, sig, &siglen, data, data_len) <= 0)
		return false;
		
	ECDSA_SIG *signature = ECDSA_SIG_new();
	if (!signature)
		return false;

	const unsigned char *p = sig;
	if (d2i_ECDSA_SIG(&signature, &p, siglen) == NULL)
		return false;

	const BIGNUM *sig_r, *sig_s;
	ECDSA_SIG_get0(signature, &sig_r, &sig_s);

        /* Store the two BIGNUMs in raw_buf. */
        unsigned int r_len = BN_num_bytes(sig_r);
        unsigned int s_len = BN_num_bytes(sig_s);
	unsigned int degree =  EC_GROUP_get_degree(EC_KEY_get0_group((EC_KEY *)key));
        unsigned int bn_len = (degree + 7) / 8;
        if ((r_len > bn_len) || (s_len > bn_len))
		return false;

        unsigned int buf_len = 2 * bn_len;
        unsigned char *raw_buf = (unsigned char *)OPENSSL_zalloc(buf_len);
        if (raw_buf == NULL)
		return false;
        BN_bn2bin(sig_r, raw_buf + bn_len - r_len);
        BN_bn2bin(sig_s, raw_buf + buf_len - s_len);

	*out = raw_buf;
	*out_len = buf_len;

	OPENSSL_free(sig);
	ECDSA_SIG_free(signature);
	EVP_PKEY_CTX_free(evp_pkey_ctx);
	EVP_PKEY_free(evp_pkey);

	return true;
}


bool
OpenSSL_SHA256_HashedID(OCTETSTRING &data, OCTETSTRING &ret)
{
	unsigned char buff[SHA256_DIGEST_LENGTH];
	unsigned char *sha = &buff[0];
				                       
	if (SHA256((const unsigned char *)data, data.lengthof(), sha) != sha)
		return false;
						                       
	ret = OCTETSTRING(8, sha + SHA256_DIGEST_LENGTH - 8);
	return true;
}


bool
OpenSSL_SHA384_HashedID(OCTETSTRING &data, OCTETSTRING &ret)
{
	unsigned char buff[SHA384_DIGEST_LENGTH];
	unsigned char *sha = &buff[0];
				                       
	if (SHA256((const unsigned char *)data, data.lengthof(), sha) != sha)
		return false;
						                       
	ret = OCTETSTRING(8, sha + SHA384_DIGEST_LENGTH - 8);
	return true;
}


bool
ECKey_GetPublicKeyComponents(void *ec_key, int &ret_nid, OCTETSTRING &ret_x, OCTETSTRING &ret_y)
{
	DEBUG_STREAM_CALLED;

	if (EC_KEY_check_key((EC_KEY *)ec_key) == 0) {
		ERROR_STREAM << "invalid EC key" << std::endl;
		return false;
	}

        const EC_GROUP *ecgroup = EC_KEY_get0_group((EC_KEY *)ec_key);
	const EC_POINT *ecpoint = EC_KEY_get0_public_key((EC_KEY *)ec_key);
	if (!ecgroup || !ecpoint)   {
		ERROR_STREAM << "cannot get EC group or/and public key" << std::endl;
		return false;
	}

	int nid = EC_GROUP_get_curve_name(ecgroup);
	if (nid != NID_X9_62_prime256v1 && nid != NID_brainpoolP256r1 && nid != NID_brainpoolP384r1)   {
		ERROR_STREAM << "'" << OBJ_nid2sn(nid) << "'(" << nid << ") not supported" << std::endl;
		return false;
	}
	DEBUG_STREAM << "EC key " << OBJ_nid2sn(nid) << "(" << nid << ")" << std::endl;

        unsigned char buf[512];
	if (EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), NULL) == 0)   {
		ERROR_STREAM << "EC point coversion failed" << std::endl;
		return false;
	}

	if (nid == NID_X9_62_prime256v1)   {
		ret_x = OCTETSTRING(32, buf+1);
		ret_y = OCTETSTRING(32, buf+33);
	}
	else if (nid == NID_brainpoolP256r1)   {
		ret_x = OCTETSTRING(32, buf+1);
		ret_y = OCTETSTRING(32, buf+33);
	}
	else if (nid == NID_brainpoolP384r1)   {
		ret_x = OCTETSTRING(48, buf+1);
		ret_y = OCTETSTRING(48, buf+49);
	}
	ret_nid = nid;

	DEBUG_STREAM_RETURNS_OK;
	return true;
}


bool
ECKey_PublicKeyFromComponents(int nid, OCTETSTRING &x, OCTETSTRING &y, OCTETSTRING &comp, int y_bit, void **ret_key)
{
	DEBUG_STREAM_CALLED;
	
	if (ret_key == NULL)   {
		ERROR_STREAM << "invalid argument" << std::endl;
		return false;
	}

        EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(nid);
        EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);

	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_start(ctx);

        EC_POINT *ecpoint = EC_POINT_new(ecgroup);
	if (y_bit != -1 && comp.is_bound())   {
		BIGNUM *bn_comp = BN_CTX_get(ctx);
        	if (!BN_bin2bn((const unsigned char *)comp, comp.lengthof(), bn_comp))
			return false;

		if (!EC_POINT_set_compressed_coordinates_GFp(ecgroup, ecpoint, bn_comp, y_bit, ctx))
			return false;
	}
	else   if (x.is_bound() && y.is_bound()) {
		BIGNUM *bn_x = BN_CTX_get(ctx);
        	if (!BN_bin2bn((const unsigned char *)x, x.lengthof(), bn_x))
			return false;

		BIGNUM *bn_y = BN_CTX_get(ctx);
        	if (!BN_bin2bn((const unsigned char *)y, y.lengthof(), bn_y))
			return false;

		if (!EC_POINT_set_affine_coordinates_GFp(ecgroup, ecpoint, bn_x, bn_y, ctx))
			return false;
	}
	else   {
		ERROR_STREAM << "invalid components" << std::endl;
		return false;
	}

	if (EC_POINT_is_on_curve(ecgroup, ecpoint, ctx) <= 0)
		return false;

	EC_KEY *key = EC_KEY_new();
        if (!EC_KEY_set_group(key, ecgroup))
		return false;
        if (!EC_KEY_set_public_key(key, ecpoint))
		return false;

	EC_POINT_free(ecpoint);
	EC_GROUP_free(ecgroup);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	*ret_key = key;

        DEBUG_STREAM_RETURNS_OK;
	return true;
}


bool 
IEEE1609dot2_SignWithSha256(OCTETSTRING &data, OCTETSTRING &signer, void *key,
		OCTETSTRING &rSig, OCTETSTRING &sSig)
{
	unsigned char buff[SHA256_DIGEST_LENGTH * 2] = {0};
	unsigned char final_hash[SHA256_DIGEST_LENGTH] = {0};
	unsigned char *sha = &buff[0];
	size_t sha_len = SHA256_DIGEST_LENGTH * 2;
	const unsigned char *signer_ptr = NULL;
	size_t signer_len = 0;

	DEBUG_STREAM_CALLED;

	if (signer.is_present() && signer.lengthof() > 0)   {
		signer_ptr = (const unsigned char *)signer;
		signer_len = signer.lengthof();
	}
	DEBUG_STREAM << "data-len:" << data.lengthof() << ", signer-len:" << signer_len << std::endl;

	if (SHA256((const unsigned char *)data, data.lengthof(), sha) != sha)   {
		ERROR_STREAM << "sha256 failed" << std::endl;
		return false;
	}

	if (SHA256(signer_ptr, signer_len, sha + SHA256_DIGEST_LENGTH) != (sha + SHA256_DIGEST_LENGTH))   {
		ERROR_STREAM << "sha256 failed" << std::endl;
		return false;
	}

	if (SHA256(sha, sha_len, final_hash) != final_hash)   {
		ERROR_STREAM << "sha256 failed" << std::endl;
		return false;
	}

        unsigned char *sig = NULL;
        size_t sig_len = 0;
	if (!OpenSSL_Sign(NULL, final_hash, SHA256_DIGEST_LENGTH, key, &sig, &sig_len))   {
		ERROR_STREAM << "OpenSSL sign failed" << std::endl;
		return false;
	}

        rSig = OCTETSTRING(sig_len/2, sig);
        sSig = OCTETSTRING(sig_len/2, sig + sig_len/2);

	OPENSSL_free(sig);
		
	DEBUG_STREAM_RETURNS_OK;
	return true;
}


bool 
IEEE1609dot2_SignWithSha384(OCTETSTRING &data, OCTETSTRING &signer,
		void *key,
		OCTETSTRING &rSig, OCTETSTRING &sSig)
{
	unsigned char buff[SHA384_DIGEST_LENGTH * 2] = {0};
	unsigned char final_hash[SHA384_DIGEST_LENGTH] = {0};
	unsigned char *sha = &buff[0];
	size_t sha_len = SHA384_DIGEST_LENGTH * 2;
	const unsigned char *signer_ptr = NULL;
	size_t signer_len = 0;

	DEBUG_STREAM_CALLED;

	if (signer.is_present() && signer.lengthof() > 0)   {
		signer_ptr = (const unsigned char *)signer;
		signer_len = signer.lengthof();
	}
	DEBUG_STREAM << "data-len:" << data.lengthof() << ", signer-len:" << signer_len << std::endl;

	if (SHA384((const unsigned char *)data, data.lengthof(), sha) != sha)   {
		ERROR_STREAM << "sha384 failed" << std::endl;
		return false;
	}

	if (SHA384(signer_ptr, signer_len, sha + SHA384_DIGEST_LENGTH) != (sha + SHA384_DIGEST_LENGTH))   {
		ERROR_STREAM << "sha384 failed" << std::endl;
		return false;
	}

	if (SHA384(sha, sha_len, final_hash) != final_hash)   {
		ERROR_STREAM << "sha384 failed" << std::endl;
		return false;
	}

        unsigned char *sig = NULL;
        size_t sig_len = 0;
	if (!OpenSSL_Sign(NULL, final_hash, SHA384_DIGEST_LENGTH, key, &sig, &sig_len))   {
		ERROR_STREAM << "OpenSSL sign failed" << std::endl;
		return false;
	}

        rSig = OCTETSTRING(sig_len/2, sig);
        sSig = OCTETSTRING(sig_len/2, sig + sig_len/2);

	OPENSSL_free(sig);
		
	DEBUG_STREAM_RETURNS_OK;
	return true;
}


bool
OpenSSL_Encrypt_aes128ccm(const OCTETSTRING &msg, OCTETSTRING &nonce, OCTETSTRING &key,
		OCTETSTRING &tag, OCTETSTRING &enc_msg)
{
        DEBUG_STREAM_CALLED;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
	tag = int2oct(0, 16);
	enc_msg = int2oct(0, msg.lengthof());

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, nonce.lengthof(), NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag.lengthof(), NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char *)key, (const unsigned char *)nonce);
        int len = 0;
        EVP_EncryptUpdate(ctx, (unsigned char*)((const unsigned char *)enc_msg), &len, (const unsigned char *)msg, msg.lengthof());
        EVP_EncryptFinal_ex(ctx, (unsigned char*)((const unsigned char *)enc_msg) + len, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tag.lengthof(), (unsigned char*)((const unsigned char *)tag));

        EVP_CIPHER_CTX_free(ctx);
        return true;
}


bool
OpenSSL_Decrypt_aes128ccm(const OCTETSTRING &enc_msg, OCTETSTRING &tag, OCTETSTRING &nonce, OCTETSTRING &skey,
		OCTETSTRING &ret_msg)
{
        DEBUG_STREAM_CALLED;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, nonce.lengthof(), NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag.lengthof(), (unsigned char *)((const unsigned char *)tag));
        EVP_DecryptInit_ex(ctx, NULL, NULL, (const unsigned char *)skey, (const unsigned char *)nonce);

        ret_msg = int2oct(0, enc_msg.lengthof());
        int len = 0;
        if (!EVP_DecryptUpdate(ctx, (unsigned char*)((const unsigned char *)ret_msg), &len, (const unsigned char *)enc_msg, enc_msg.lengthof()))   {
                ERROR_STREAM << "DecryptUpdate error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
                return false;
        }
        EVP_CIPHER_CTX_free(ctx);

        DEBUG_STREAM_RETURNS_OK;
        return true;
}


int
OpenSSL_txt2nid(const char *txt)
{
	return OBJ_txt2nid(txt);
}


void
OpenSSL_setup(void)
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_clear_error();
}


void
OpenSSL_cleanup(void)
{
        CONF_modules_free();
        ENGINE_cleanup();
        CONF_modules_unload(1);
        ERR_free_strings();
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
}


bool
ECKey_DecompressPublicKey(int nid, OCTETSTRING &in_comp_key, int in_comp_mode,
		OCTETSTRING &ret_x, OCTETSTRING &ret_y)
{
	BIGNUM *xy = NULL;
	OCTETSTRING xy_oct;
	int xy_oct_len = 0;
	unsigned char *xy_oct_ptr = NULL;
	bool ret = false;

	// OCTETSTRING comp_key;
	// int comp_key_mode;

	DEBUG_STREAM_CALLED;

	BN_CTX *bn_ctx = BN_CTX_new();
	BIGNUM *compressed_key = BN_new();
    	BN_bin2bn((const unsigned char *)(in_comp_key), in_comp_key.lengthof(), compressed_key);

	EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(nid);
	EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);
	EC_POINT *ecpoint = EC_POINT_new(ecgroup);

	EC_KEY *eckey = EC_KEY_new();;
	EC_KEY_set_conv_form(eckey, POINT_CONVERSION_UNCOMPRESSED);

	if (EC_KEY_set_group(eckey, ecgroup) == 0)   {
		ERROR_STREAM << "set EC group failed" << std::endl;
		goto fin;
	}
	if (EC_KEY_set_public_key(eckey, ecpoint) == 0)   {
		ERROR_STREAM << "set EC public key failed" << std::endl;
		goto fin;
	}
	if (EC_POINT_set_compressed_coordinates_GFp(ecgroup, ecpoint, compressed_key, in_comp_mode, bn_ctx) == 0)   {
		ERROR_STREAM << "set EC compressed coordinates failed" << std::endl;
		goto fin;
	}

	xy = EC_POINT_point2bn(ecgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, NULL, bn_ctx);
	if (xy == NULL)  {
		ERROR_STREAM << "cannot transform point to BN" << std::endl;
		goto fin;
	}

	EC_KEY_set_public_key(eckey, ecpoint);

	xy_oct = int2oct(0, BN_num_bytes(xy));
	xy_oct_ptr = (unsigned char *)((const unsigned char *)xy_oct);
  	BN_bn2bin(xy, xy_oct_ptr);
	
	xy_oct_len = xy_oct.lengthof();
	if ((xy_oct_len & 0x01) == 0 || *xy_oct_ptr != 0x04) {
		ERROR_STREAM << "invalid public key BN" << std::endl;
		goto fin;
	}
	
  	ret_x = OCTETSTRING((xy_oct_len - 1) / 2, xy_oct_ptr + 1);
  	ret_y = OCTETSTRING((xy_oct_len - 1) / 2, xy_oct_ptr + 1 + (xy_oct_len - 1) / 2);

	ret = true;
	DEBUG_STREAM_RETURNS_OK;
fin:
	BN_clear_free(xy);
	EC_KEY_free(eckey);
	EC_POINT_free(ecpoint);
	EC_GROUP_clear_free (ecgroup);
	BN_clear_free(compressed_key);
	BN_CTX_free(bn_ctx);

	return ret;
}


bool
ECKey_KeyComponentsFromString(int nid, const char *prvkey_str, 
		OCTETSTRING &ret_x, OCTETSTRING &ret_y,
		OCTETSTRING &ret_comp_key, INTEGER &ret_comp_key_mode)
{
	DEBUG_STREAM_CALLED;
	DEBUG_STREAM << "nid:" << nid << ", prvkey" << std::endl;

	EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid);
	OCTETSTRING prvkey_oct;

	EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_UNCOMPRESSED);
	EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);

	prvkey_oct = str2oct(prvkey_str);

	BN_CTX *bn_ctx = BN_CTX_new();
	BIGNUM *bn = BN_new();
	BN_bin2bn(((const unsigned char*)prvkey_oct), prvkey_oct.lengthof(), bn);
	
	EC_POINT *ec_point = EC_POINT_new(ec_group);
    	EC_POINT_mul(ec_group, ec_point, bn, nullptr, nullptr, bn_ctx);
  
	EC_KEY_set_private_key(ec_key, bn);
    	if (EC_KEY_check_key(ec_key) == 0) {
		ERROR_STREAM << "invalid EC key" << std::endl;
		return false;
	}
	BN_clear_free(bn);

	EC_KEY_set_public_key(ec_key, ec_point);

	BIGNUM *bn_xy = BN_new();
	EC_POINT_point2bn(ec_group, ec_point, POINT_CONVERSION_UNCOMPRESSED, bn_xy, bn_ctx);
	if (BN_num_bytes(bn_xy) == 0) {
		BN_clear_free(bn_xy);
		ERROR_STREAM << "point to BN failed" << std::endl;
		return false;
	}

	OCTETSTRING oct_xy = int2oct(0, BN_num_bytes(bn_xy));
	BN_bn2bin(bn_xy, (unsigned char*)((const unsigned char *)oct_xy));
	if ((oct_xy.lengthof() % 2) != 0)
		oct_xy = OCTETSTRING(oct_xy.lengthof() - 1, 1 + (const unsigned char *)oct_xy);

	BN_clear_free(bn_xy);

	const int l = oct_xy.lengthof() / 2;
	ret_x = OCTETSTRING(l, (const unsigned char *)oct_xy);
	ret_y = OCTETSTRING(l, l + (const unsigned char *)oct_xy);

	// Compressed
	int len = EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
	if (len == 0) {
		ret_comp_key = OCTETSTRING(0, NULL);
	}
	else {
    		ret_comp_key = int2oct(0, len);
		if (EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_COMPRESSED, (unsigned char*)((const unsigned char *)ret_comp_key), len, bn_ctx) == 0) {
      			ret_comp_key = OCTETSTRING(0, nullptr);
		}
		else { // Remove first byte
			ret_comp_key_mode = oct_xy[0].get_octet() & 0x01;
			ret_comp_key = OCTETSTRING(ret_comp_key.lengthof() - 1, 1 + (const unsigned char *)ret_comp_key);
		}
	}

	EC_POINT_free(ec_point);

	DEBUG_STREAM_RETURNS_OK;
	return true;
}


bool
ECKey_NewKey(int nid,
		void **ret_eckey,
		OCTETSTRING &ret_prvkey_oct,
		OCTETSTRING &ret_x, OCTETSTRING &ret_y,
		OCTETSTRING &ret_comp_key, INTEGER &ret_comp_key_mode)
{
	EC_KEY *ec_key = NULL;

	DEBUG_STREAM_CALLED;
        
        ec_key = EC_KEY_new_by_curve_name(nid);
        if (ec_key == NULL)   {
                ERROR_STREAM << "failed to generate new EC key" << std::endl;
                return false;
        }
        EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

	if (!EC_KEY_generate_key(ec_key))   {
		ERROR_STREAM << "failed to generate new EC key" << std::endl;
		return false;
	}

	const EC_GROUP *ec_group = ::EC_KEY_get0_group(ec_key);
	const EC_POINT *ec_point = EC_KEY_get0_public_key(ec_key);
        BN_CTX *bn_ctx = BN_CTX_new();
	BIGNUM *x = ::BN_new();
	BIGNUM *y = ::BN_new();

	int size = 0;
	switch(nid)   {
	case NID_X9_62_prime256v1:
	case NID_brainpoolP256r1:
		size = 32;
		::EC_POINT_get_affine_coordinates_GFp(ec_group, ec_point, x, y, bn_ctx);
		break;
	case NID_brainpoolP384r1:
		size = 48;
		::EC_POINT_get_affine_coordinates_GFp(ec_group, ec_point, x, y, bn_ctx);
		break;
	default:
		ERROR_STREAM << "Unsupported EC curve " << OBJ_nid2sn(nid) << std::endl;
		return false;
	}

	const BIGNUM *bn_prvkey = ::EC_KEY_get0_private_key(ec_key);
  	ret_prvkey_oct = int2oct(0, size);
  	BN_bn2bin(bn_prvkey, (unsigned char *)((const unsigned char *)ret_prvkey_oct));
	
	ret_x = int2oct(0, size);
	BN_bn2bin(x, (unsigned char *)((const unsigned char *)ret_x));

	ret_y = int2oct(0, size);
	BN_bn2bin(y, (unsigned char *)((const unsigned char *)ret_y));

	int comp_len = EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
  	if (comp_len == 0)   {
		ERROR_STREAM << "Unsupported EC curve " << OBJ_nid2sn(nid) << std::endl;
		return false;
	}

  	ret_comp_key = int2oct(0, comp_len);
  	if (EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_COMPRESSED, (unsigned char *)((const unsigned char *)ret_comp_key), comp_len, bn_ctx) == 0) {
		ret_comp_key  = OCTETSTRING(0, NULL);
	}
	else {
		ret_comp_key_mode = INTEGER(ret_comp_key[0].get_octet() & 0x01);
    		ret_comp_key = OCTETSTRING(ret_comp_key.lengthof() - 1, 1 + (const unsigned char *)(ret_comp_key));
	}

	BN_CTX_free(bn_ctx);
	BN_clear_free(x);
	BN_clear_free(y);

	if (ret_eckey != NULL)
		*ret_eckey = ec_key;

	DEBUG_STREAM_RETURNS_OK;
	return true;
}


int
ECKey_GetNid(void *key)
{
	return EC_GROUP_get_curve_name(EC_KEY_get0_group((EC_KEY *)key));
}


void
ECKey_Free(void *key)
{
	EC_KEY_free((EC_KEY *)key);
}


bool
ECKey_DerivateSKey_aes128ccm(void *in_eckey,
	const OCTETSTRING &x, const OCTETSTRING &y,
	const OCTETSTRING &salt,
	OCTETSTRING &aes_skey,
	OCTETSTRING &enc_skey,
	OCTETSTRING &tag)
{
	DEBUG_STREAM_CALLED;

	EC_KEY *ec_key = (EC_KEY *)in_eckey;
	if (EC_KEY_check_key(ec_key) == 0)    {
		ERROR_STREAM << "not valid EC key" << std::endl;
		return false;
	}

	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
	int nid = EC_GROUP_get_curve_name(ec_group);
	OCTETSTRING shared_skey = int2oct(0, (EC_GROUP_get_degree(ec_group) + 7) / 8);

	// SymmetricEncryptionKey ::= CHOICE  { aes128Ccm ...
  	int k_enc_len, k_mac_len;
	switch(nid)   {
	case NID_X9_62_prime256v1:
	case NID_brainpoolP256r1:
    		k_enc_len = 16;
    		k_mac_len = 32;
		break;
	case NID_brainpoolP384r1:
    		k_enc_len = 24;
    		k_mac_len = 48;
		break;
	default:
		ERROR_STREAM << "not supported EC curve '" << nid << "'" << std::endl;
		return false;
	}

	OCTETSTRING raw = int2oct(4, 1);
	raw += x;
	raw += y;
	
	BIGNUM *pubkey_bn = BN_bin2bn((const unsigned char *)(raw), raw.lengthof(), NULL);
	EC_POINT *ec_point = EC_POINT_new(ec_group);
	EC_POINT_bn2point(ec_group, pubkey_bn, ec_point, NULL);
	BN_clear_free(pubkey_bn);

	// Generate the shared secret key (Key Agreement)
	int rv = ECDH_compute_key((unsigned char *)((const unsigned char *)shared_skey), shared_skey.lengthof(), ec_point, ec_key, NULL);
    	EC_POINT_free(ec_point);
	if (rv <= 0)   {
		ERROR_STREAM << "cannot compute shared secret" << std::endl;
		return false;
	}
	dump_ttcn_object(shared_skey, "Shared SKey: ");

	// Derive the shared secret key
	OCTETSTRING digest;
	if (!kdf2_sha256(shared_skey, salt, k_enc_len + k_mac_len, digest))   {
		ERROR_STREAM << "KDF2 failed" << std::endl;
		return false;
	}
	dump_ttcn_object(digest, "Digest: ");

	OCTETSTRING k1(k_enc_len, (const unsigned char *)digest);
	dump_ttcn_object(k1, "K1: ");

  	if (!aes_skey.is_bound()) {
		BIGNUM *bn = BN_new();
    		BN_pseudo_rand(bn, k_enc_len * 8, -1, 0);
    		aes_skey = int2oct(0, k_enc_len);
    		BN_bn2bin(bn, (unsigned char*)((const unsigned char *)aes_skey));
		BN_free(bn);
	}

	enc_skey = k1 ^ aes_skey;
	dump_ttcn_object(enc_skey, "Enc AES SKey: ");
  
	// Extract K2 and generate Tag vector
	OCTETSTRING k2(k_enc_len * 2, k_enc_len + (const unsigned char *)digest);
	dump_ttcn_object(k2, "K2: ");

  	if (!hmac_sha256(enc_skey, k2, tag))   {
		ERROR_STREAM << "tag HMAC SHA256 failed" << std::endl;
		return false;
	}
 
	DEBUG_STREAM_RETURNS_OK;
	return true;
}


