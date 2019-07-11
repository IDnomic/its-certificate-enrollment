#include <fstream>
#include <vector>
#include <iterator>
#include <iostream>
#include <exception>
#include <boost/program_options.hpp>

#include "TTCN3.hh"
#include "EtsiTs103097Module.hh"

#include "its/itspki-debug.hh"
#include "its/itspki-internal-data.hh"
#include "its/itspki-session.hh"
#include "its/utils.hh"

#include "itspki-cmd-args.hh"

using namespace boost::program_options;
namespace po  = boost::program_options;


bool
ParseEcEnrollmentCmdArguments(ItsPkiCmdArguments cmd_args, ItsPkiInternalData &idata)
{
	DEBUG_STREAM_CALLED;

	// ITS Technical Key
	void *key = NULL;
	if (!cmd_args.its_tkey.empty())
		key = ECKey_ReadPrivateKey(cmd_args.its_tkey.c_str());	
	else if (!cmd_args.its_tkey_b64.empty())
		key = ECKey_ReadPrivateKeyB64(cmd_args.its_tkey_b64.c_str());	
	if (!idata.SetItsTechnicalKey(key))   {
		ERROR_STREAM << "EC enroll: Missing or invalid technical key" << std::endl;
		return false;
	}
	
	// ITS Ec Encryption Key
	if (cmd_args.its_ec_ekey_enable)   {
		key = NULL;
		if (!cmd_args.its_ec_ekey.empty())
			key = ECKey_ReadPrivateKey(cmd_args.its_ec_ekey.c_str()); 
		else if (!cmd_args.its_ec_ekey_b64.empty())
			key = ECKey_ReadPrivateKeyB64(cmd_args.its_ec_ekey_b64.c_str()); 
		else 
			key = ECKey_GeneratePrivateKey();
		idata.SetItsEcEncryptionKey(key);
	}

	// ITS Ec Verification Key
	key = NULL;
	if (!cmd_args.its_ec_vkey.empty())
		key = ECKey_ReadPrivateKey(cmd_args.its_ec_vkey.c_str()); 
	else if (!cmd_args.its_ec_vkey_b64.empty())
		key = ECKey_ReadPrivateKeyB64(cmd_args.its_ec_vkey_b64.c_str()); 
	else
		key = ECKey_GeneratePrivateKey();
	idata.SetItsEcVerificationKey(key);

	// Parse EA certificate
	OCTETSTRING blob;
	if (!cmd_args.eacertfile.empty())   {
		read_bytes(cmd_args.eacertfile, blob);
	}
	else if (!cmd_args.eacert_b64.empty())   {
		blob = decode_base64(cmd_args.eacert_b64.c_str());
	}
	else   {
		ERROR_STREAM << "EC enroll: EA certificate is mandatory "<< std::endl;
		return false;
	}
	if (!idata.SetEAEncryptionKey(blob))   {
		ERROR_STREAM << "EC enroll arguments: cannot set EA encryption key from cert file or b64-string " << cmd_args.eacertfile << "'" << std::endl;
		return false;
	}

	// Create/Set ITS canonical ID
	if (!idata.SetCanonicalID(cmd_args.its_canonical_id, cmd_args.its_name_header, idata.GetItsTechnicalKey()))   {
		ERROR_STREAM << "EC enroll arguments: cannot set ITS canonical ID" << std::endl;
		return false;
	}
	DEBUG_STREAM << "ITS Canonical ID: '" << idata.GetCanonicalId() << "'" << std::endl;

	// Set permissions
	// if (!idata.SetAidSsp(cmd_args.app_perms_psid, cmd_args.app_perms_ssp_opaque, cmd_args.app_perms_ssp_bitmap))   {
	if (!idata.EcAddAidSsp(cmd_args.app_perms_psid, cmd_args.app_perms_ssp_opaque, cmd_args.app_perms_ssp_bitmap))   {
		ERROR_STREAM << "EC enroll arguments: cannot set ITS AID SSP list" << std::endl;
		return false;
	}
	DEBUG_STREAM << "ITS AID-SSP number of elements " << idata.EcGetAppPermsSsp().n_elem() << std::endl;

	// Set ITS Hash algorithm
	if (!idata.SetHashAlgorithm(cmd_args.GetHashAlgorithm()))   {
		ERROR_STREAM << "EC enroll arguments: cannot set Hash algorithm" << std::endl;
		return false;
	}

	// Save enrollment results: ITS EC certificate and verification key
	if (cmd_args.its_ec_cert_save2file.empty())
		idata.SetItsEcCertSave2File(idata.GetCanonicalId() + "-EC-cert.oer");
	else
		idata.SetItsEcCertSave2File(cmd_args.its_ec_certfile);
	
	if (cmd_args.its_ec_vkey_save2file.empty())
		idata.SetItsEcVerificationKeySave2File(idata.GetCanonicalId() + "-EC-vkey.pem");
	else
		idata.SetItsEcVerificationKeySave2File(cmd_args.its_ec_vkey_save2file);

	// Save enrollment results: ITS EC encryption key
	if (cmd_args.its_ec_ekey_enable)   {
		if (cmd_args.its_ec_ekey_save2file.empty())
			idata.SetItsEcEncryptionKeySave2File(idata.GetCanonicalId() + "-EC-ekey.pem");
		else
			idata.SetItsEcEncryptionKeySave2File(cmd_args.its_ec_ekey_save2file);
	}

	DEBUG_STREAM_RETURNS_OK;
	return true;
}


bool
ParseAtEnrollmentCmdArguments(ItsPkiCmdArguments cmd_args, ItsPkiInternalData &idata)
{
	DEBUG_STREAM_CALLED;
	
	void *key = NULL;
	if (!cmd_args.its_at_vkey.empty())
		key = ECKey_ReadPrivateKey(cmd_args.its_at_vkey.c_str()); 
	else if (!cmd_args.its_at_vkey_b64.empty())
		key = ECKey_ReadPrivateKeyB64(cmd_args.its_at_vkey_b64.c_str()); 
	else
		key = ECKey_GeneratePrivateKey();
	idata.SetItsAtVerificationKey(key);

	if (cmd_args.its_at_ekey_enable)   {
		key = NULL;
		if (!cmd_args.its_at_ekey.empty())
			key = ECKey_ReadPrivateKey(cmd_args.its_at_ekey.c_str()); 
		else
			key = ECKey_GeneratePrivateKey();
		idata.SetItsAtEncryptionKey(key);
	}

	// Parse EA certificate
	OCTETSTRING blob;
	if (!cmd_args.eacertfile.empty())   {
		read_bytes(cmd_args.eacertfile, blob);
	}
	else if (!cmd_args.eacert_b64.empty())   {
		blob = decode_base64(cmd_args.eacert_b64.c_str());
	}
	else   {
		ERROR_STREAM << "AT enroll: EA certificate is mandatory "<< std::endl;
		return false;
	}
	if (!idata.SetEAEncryptionKey(blob))   {
		ERROR_STREAM << "AT enroll arguments: cannot set EA encryption key from cert file or b64-string " << cmd_args.eacertfile << "'" << std::endl;
		return false;
	}

	blob.clean_up();
	if (!cmd_args.aacertfile.empty())   {
		read_bytes(cmd_args.aacertfile, blob);
	}
	else if (!cmd_args.aacert_b64.empty())   {
		blob = decode_base64(cmd_args.aacert_b64.c_str());
	}
	else   {
		ERROR_STREAM << "AT enroll: AA certificate is mandatory "<< std::endl;
		return false;
	}
	if (!idata.SetAAEncryptionKey(blob))   {
		ERROR_STREAM << "AT enroll arguments: cannot set AA encryption key from cert file or b64-string " << cmd_args.aacertfile << "'" << std::endl;
		return false;
	}

	blob.clean_up();
	if (!cmd_args.its_ec_certfile.empty())   {
		read_bytes(cmd_args.its_ec_certfile, blob);
	}
	else if (!cmd_args.its_ec_cert_b64.empty())   {
		blob = decode_base64(cmd_args.its_ec_cert_b64.c_str());
	}
	else   {
		ERROR_STREAM << "AT enroll: ITS EC certificate is mandatory "<< std::endl;
		return false;
	}
	if (!idata.SetItsEcId(blob))   {
		ERROR_STREAM << "AT enroll arguments: cannot set ITS EC ID" << std::endl;
		return false;
	}

	key = NULL;
	if (!cmd_args.its_ec_vkey.empty())
		key = ECKey_ReadPrivateKey(cmd_args.its_ec_vkey.c_str()); 
	else if (!cmd_args.its_ec_vkey_b64.empty())
		key = ECKey_ReadPrivateKeyB64(cmd_args.its_ec_vkey_b64.c_str()); 
	idata.SetItsEcVerificationKey(key);

	// Create/Set ITS canonical ID
	if (!idata.SetCanonicalID(cmd_args.its_canonical_id, cmd_args.its_name_header, idata.GetItsTechnicalKey()))   {
		ERROR_STREAM << "AT enroll arguments: cannot set ITS canonical ID" << std::endl;
		return false;
	}
	DEBUG_STREAM << "ITS Canonical ID: '" << idata.GetCanonicalId() << "'" << std::endl;
	
	// Set permissions
	if (!idata.AtAddAidSsp(cmd_args.app_perms_psid, cmd_args.app_perms_ssp_opaque, cmd_args.app_perms_ssp_bitmap))   {
		ERROR_STREAM << "EC enroll arguments: cannot set ITS AID SSP list" << std::endl;
		return false;
	}
	dump_ttcn_object(idata.AtGetAppPermsSsp(), "ITS AT AID-SSP: ");

	// Set ITS Hash algorithm
	if (!idata.SetHashAlgorithm(cmd_args.GetHashAlgorithm()))   {
		ERROR_STREAM << "EC enroll arguments: cannot set Hash algorithm" << std::endl;
		return false;
	}

	// Save enrollment results: ITS AT certificate and verification key
	if (!cmd_args.its_at_cert_save2file.empty())
		idata.SetItsAtCertSave2File(cmd_args.its_at_certfile);
	else if (!idata.GetCanonicalId().empty())
		idata.SetItsAtCertSave2File(idata.GetCanonicalId() + "-AT-cert.oer");

	if (!cmd_args.its_at_vkey_save2file.empty())
		idata.SetItsAtVerificationKeySave2File(cmd_args.its_at_vkey_save2file);
	else if (!idata.GetCanonicalId().empty())
		idata.SetItsAtVerificationKeySave2File(idata.GetCanonicalId() + "-AT-vkey.pem");

	// Save enrollment results: ITS AT encryption key
	if (cmd_args.its_at_ekey_enable)   {
		if (!cmd_args.its_at_ekey_save2file.empty())
			idata.SetItsAtEncryptionKeySave2File(cmd_args.its_at_ekey_save2file);
		else if (!idata.GetCanonicalId().empty())
			idata.SetItsAtEncryptionKeySave2File(idata.GetCanonicalId() + "-AT-ekey.pem");
	}

	DEBUG_STREAM_RETURNS_OK;
        return true;
}


bool
ParseItsRegisterCmdArguments(ItsPkiCmdArguments cmd_args, ItsPkiInternalData &idata)
{
	DEBUG_STREAM_CALLED;

	if (cmd_args.profile.empty())   {
		ERROR_STREAM << "ItsRegister: missing mandatory 'profile' argument" << std::endl;
		return false;
	}
	idata.SetProfile(cmd_args.profile);

	// ITS Technical Key
	void *key = NULL;
	if (!cmd_args.its_tkey.empty())
		key = ECKey_ReadPrivateKey(cmd_args.its_tkey.c_str());	
	else if (!cmd_args.its_tkey_b64.empty())
		key = ECKey_ReadPrivateKeyB64(cmd_args.its_tkey_b64.c_str());	
	else
		key = ECKey_GeneratePrivateKey();
	if (!idata.SetItsTechnicalKey(key))   {
		ERROR_STREAM << "EC enroll: Missing or invalid technical key" << std::endl;
		return false;
	}

	// Create/Set ITS canonical ID
	if (!idata.SetCanonicalID(cmd_args.its_canonical_id, cmd_args.its_name_header, idata.GetItsTechnicalKey()))   {
		ERROR_STREAM << "EC enroll arguments: cannot set ITS canonical ID" << std::endl;
		return false;
	}
	DEBUG_STREAM << "ITS Canonical ID: '" << idata.GetCanonicalId() << "'" << std::endl;

	DEBUG_STREAM_RETURNS_OK;
        return true;
}


