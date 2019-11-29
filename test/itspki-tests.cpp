#include "gtest/gtest.h"
#include <boost/program_options.hpp>
#include "TTCN3.hh"
#include "itspki-cmd-args.hh"
#include "itspki-common.hh"
#include "its/itspki-internal-data.hh"
#include "its/itspki-session.hh"


#define ITS_PKI_DEBUG 1

const char *profile = "TestDemoProfile";
const char *its_prefix_id = "BENCH-ITSPKI-UTOPIA";
const char *its_serial_id_hex = "9891EED436ADBC62";
const char *its_canonical_id_str = "BENCH-ITSPKI-UTOPIA.9891EED436ADBC62";
OCTETSTRING its_canonical_id, its_serial_id;

std::string its_tkey_pubkey_id = "9891EED436ADBC62";
const char *its_tkey =    "MHcCAQEEIJhYN95tGd6fvySjcQXxG1mzQ2QEPKdIQFJa/FjtlTE+oAoGCCqGSM49AwEHoUQDQgAE0XKg7gn78lEHh3p0YD54oaYWy8AVC7vaP9yy5gcos89bDqwVSqyiqlidEYfyDaIGg2iSNKRHVQ4gOUkVmsax8w==";
const char *its_tpubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0XKg7gn78lEHh3p0YD54oaYWy8AVC7vaP9yy5gcos89bDqwVSqyiqlidEYfyDaIGg2iSNKRHVQ4gOUkVmsax8w==";

const char *ec_psidssp_seq = "623:01C0";
const char *its_ec_ekey = "MHcCAQEEIGxG88tF++Y8l4tb58u50D7U4rZw0cm02u3Odq/Yb1BpoAoGCCqGSM49AwEHoUQDQgAEofoXTU2fkIiVSOD3svFGUB8qa19ednPvuZbjml3zIkNiMRgyDeJE9QWwwRRCzzhKhxZssaaGzNuL8/I1J+6OqA==";
const char *its_ec_vkey = "MHcCAQEEIH0sgR6prK5aGdW5Ne/5jUl3dHRI5O8pGTJqc+xKpQWXoAoGCCqGSM49AwEHoUQDQgAEl17NaS6FEMKXU2/VUnEl/GzLUcmZKjzqI/gOi096HZmwVeZ9k6PJgkIpp2dAgdsqL7/1pKJuMxsdv/Xg2XFOhQ==";
const char *its_ec_cert = "gAMAgGLAQtRS0W66EYEkM2ZiZTdmNzktZTBhMS00ZDMxLWIzNjQtNDQyMGU0MmJlNmMzAAAAAAAd6ewKgpqAAQGAAgJvgQMCAcAAgISh+hdNTZ+QiJVI4Pey8UZQHyprX152c++5luOaXfMiQ2IxGDIN4kT1BbDBFELPOEqHFmyxpobM24vz8jUn7o6ogICEl17NaS6FEMKXU2/VUnEl/GzLUcmZKjzqI/gOi096HZmwVeZ9k6PJgkIpp2dAgdsqL7/1pKJuMxsdv/Xg2XFOhYGApb4TWDNNGt9jWcS95Hj15I8aWYYCtN0PuFRfXAYiCkFJCdCGHCphkb268psUfgn1eUvfr1dHqnhJlKzuApgENA==";


const char *ea_cert = "gAMAggi/FANQ1el8JxmBD1VUT1BJQV9URVNUX0VBMQAAAAAAHcK+dYYABQEBgAICb4EDAgEOAQEAgAEBgAICb4IGAgHAAv8/AICC4Wn0L7AogBtttxf156N6f7sXy5WoEb8iRYj28lb+jdyAgYJF3E+/QpEOGEO8M+1XUuN4H6hEMq9td8PzW8EF6Ek4QoJhgCN0lAeJ/2lf6CtmlpHAliOKUGSgYg2wu5oh5MenzGjP/qTmJrTyuykdeUB8osYt9orBFpTj3lR5lkCgmqnr8Zv+C1pLbW8dDEir2QObyQQDhbd9k7Ltuh3kB0LP89aoNw==";
const char *aa_cert = "gAMAggi/FANQ1el8JxmBD1VUT1BJQV9URVNUX0FBMQAAAAAAHcK+dYYABQEBgAICb4EDAgEyAQEAgAEHgAEkgggDAf/8A/8AA4ABJYIKBAH///8E/wAAAIABiYIGAgHgAv8fgAGKggYCAcAC/z+AAYuCDgYBAAAA//gG/wAAAAAHgAGMggoEAf//4AT/AAAfAAGNAICC1820Ad2fWnZZzKcV970uiENWOdYYgRqLCwost2vhvu+AgIIFBaFQRIiYs5sNqPeoLSysvVJWofSHTIY6vvqI9WxnIIJhgEm1osLUkL5r0B9QPBFv/Z9wrTQfovXxAn9kvOhzY0mKoqz5K+t0DyXRaGhzK2ehhWz8W+HsVWwr3TuzDRCAVlEbVmEhjoaotH655SFS+xoAPcCfblgWP+oDxjyrOp5vgg==";

const char *ea_vprvkey =  "MHgCAQEEIB0va/C6G1nBbfXZlEKGscMb2Asz60HEMdaUyko1l8rIoAsGCSskAwMCCAEBB6FEA0IABEXcT79CkQ4YQ7wz7VdS43gfqEQyr213w/NbwQXoSThCSiDW8ixouwsa1zRYgNIsJ0jxxwDHonSFY1+AKGxbJ0Y=";
const char *ea_eprvkey =  "MHcCAQEEIAPAS9anffX3jhVDQyt/DfiJS7XL6OKA8FMxLtxieCYsoAoGCCqGSM49AwEHoUQDQgAE4Wn0L7AogBtttxf156N6f7sXy5WoEb8iRYj28lb+jdw+gTEFFOAT5M2HHAJcH2wFJhRwEjHuTbXH0qgQh+Lvdg==";

const char *at_psidssp_seq = "36:010000";

const char *aa_eprvkey = "MHcCAQEEIN5HgM/nP7yW2GQz3/SFW1ztfXVS+4w8hBwDKPurrY4+oAoGCCqGSM49AwEHoUQDQgAE1820Ad2fWnZZzKcV970uiENWOdYYgRqLCwost2vhvu996uBQVgU2e7PzcNMpqJqCFDiAsTgx4Yv9azxbxtkdPg==";
const char *aa_vprvkey = "MHcCAQEEIAyypth3nkaRXCr+ZMfQ7GnJCSjJcz86h/Z8DEx2FDpioAoGCCqGSM49AwEHoUQDQgAEBQWhUESImLObDaj3qC0srL1SVqH0h0yGOr76iPVsZyBy/azdoDMitV46iaolvM6z6lEer1c/WhDBGkaLKTtzYA==";

int ec_inner_request_cert_valid_from = 0x1DE8809A;
const char *blob_ec_inner_request = "001B42454E43482D495453504B492D55544F5049419891EED436ADBC6201808084975ECD692E8510C297536FD5527125FC6CCB51C9992A3CEA23F80E8B4F7A1D99B055E67D93A3C9824229A7674081DB2A2FBFF5A4A26E331B1DBFF5E0D9714E85008084A1FA174D4D9F90889548E0F7B2F146501F2A6B5F5E7673EFB996E39A5DF32243623118320DE244F505B0C11442CF384A87166CB1A686CCDB8BF3F23527EE8EA8241DE8809A86000301018002026F81030201C0";
const char *blob_ec_enrollment_request = "038201018262C042D452D16EBA80837C64649CC59F37AFB0271D04A05D68A577DCFE6636F9297E0D81F30FF5C426FCDB4B2902D67D6EFBB9B1AAADC89581A14E38B9401DAE42F7A74F0754DD13E2E180C0179481C7F8FE47DEA564F582017893DA95AC0E471B28D2A8E3FD7926233A9D0BC606574E97FECFD24DC424195B4DFD54BF65272E09EE509CB27F128AB988BD2D425FAEBBD3D7E4F08F383E0A595E566DC689020ED8EBA39914EC0B084ACC25F5DBB71F1705D417A420FE7572B0B6DC22AA183F8ACF6F45FAFB8F0BD0F8A27B4916B680F571AC964E9EF9E1B08FDA627C5E6A0C4022DEFACCDC2A16983DB6F7D040ECB3EC0CFC153E7EC8A05BF1D2B3AD020D8921BCEC7DEC8624FDF192F28AC370A50ED209CE637FF5ACE2B238CA9ADC41237BB37716F23A45600CFB4E8F632E3EDE3E52B167CC26BF72D099E4D4DABCC03B6A66706D64EE88C876E28ACC0D44A5EEB7B07E5E2456F0199F220501AD7E631C156781D379AC935764719F0AE62DEE82EE1F70F3A0246D816EB0B6481E994DEFCD289506471A10F26A413CD5090E378269073B5A92CB8EEDC5D8A8779C35E92634064A2316A9C07F78A840E1E1CAB69B291E0E9B25388BCE650A68CFE2FD903057E79A2C7628D065A8D1D1F0E54CC50718E3986C";

const char *blob_ec_enrollment_response = "0382010180148E2CFA81A133B480BD0C5F317F7BC317F8D7992D820196CF81AE63C8F883B99D56D4C8462F81A068857D11F5DBE8B0E463C560D88DEF53C1CBC370A67805407978EC36DD9ED0B13DC8CCD46CD8A80ACE5BFC5F931452FFFC675B6F547EB79337CF32C4E52D340D8153FEA8D992C9282A6032F41D6B3C4FFDA268B234C008A71174A7EA916BF53A7BBE2468A837797E85230D73ACB78357CD560677639A6C52F39DE3E566E3EA962D6CBF64800D1860C4681A8576F5FF8228BA1AA99769918349BADF934BEE27C2852E69BC06FF8E1FE26AF4A3F5F00A4A60306E957CA7BDA762DF960DAD84D9246726A3F8EF812BE2CA2D4B5E2646998742ED8467FC588A2399A18C112433CA5429508CB80C1167C5D00B53E40B03B191CA0F96D1BE7F68A57EC55A3F121E263B378838872248852E4BFF5A4BB190A1553CD279347AC6B63A680464F105737AD307F3BD27010F7517374E314516EFD7DB7EA8D7E6520949499AB2010492D609D0E4C49B7DF102B972E31F3712A74D409991E944ABDD9BBDFD0BD43C657E4712A68DDF75C85E6FCE3B792D6C5324DDE487E0E2D214181C5ABDE17B603884BABDA2E0AD75542565";
const char *blob_ec_enrollment_response_skey_id = "148E2CFA81A133B4";
const char *blob_ec_enrollment_response_aes_key = "FAA06B1C7FA75763EEF537846B7906CD";
const char *blob_ec_enrollment_response_tag =     "1EFFBF04D459E558D9E7FA632A351AFE";


void defaultCmdArgs(ItsPkiCmdArguments &cmd_args)
{
	// ITS Regiser
	cmd_args.its_canonical_id = its_canonical_id_str; 
	cmd_args.its_prefix_id = std::string(its_prefix_id);
	cmd_args.its_serial_id_hex = std::string(its_serial_id_hex);
	cmd_args.profile = std::string(profile);
	cmd_args.its_tkey_b64 = std::string(its_tkey);
	cmd_args.ec_psidssp_seq = std::string(ec_psidssp_seq);

	cmd_args.its_ec_vkey_b64 = std::string(its_ec_vkey);
	cmd_args.its_ec_cert_b64 = std::string(its_ec_cert);
	cmd_args.its_ec_ekey_b64 = std::string(its_ec_ekey);
	cmd_args.its_ec_ekey_enable = true;

	cmd_args.at_psidssp_seq = std::string(at_psidssp_seq);
	cmd_args.its_at_ekey_enable = true;

	cmd_args.eacert_b64 = std::string(ea_cert);
	cmd_args.aacert_b64 = std::string(aa_cert);
}


TEST(InternalData_canonicalID, add)
{
	ItsPkiCmdArguments cmd_args;
	defaultCmdArgs(cmd_args);

	ItsPkiInternalData idata;

	std::string empty = "";

	OCTETSTRING pid = OCTETSTRING(strlen(its_prefix_id), (const unsigned char *)its_prefix_id);
	OCTETSTRING sid = str2oct(its_serial_id_hex);
	OCTETSTRING cid = pid + sid;

	ASSERT_TRUE(idata.SetItsCanonicalID(its_canonical_id_str, empty, empty, NULL));
	ASSERT_EQ(idata.GetItsPrefixId(), std::string(its_prefix_id));
	ASSERT_EQ(idata.GetItsSerialId(), str2oct(its_serial_id_hex));
	ASSERT_EQ(idata.GetItsCanonicalId(), cid);
	ASSERT_FALSE(idata.IsGenerateItsSerialId());

	ASSERT_TRUE(idata.SetItsCanonicalID(empty, its_prefix_id, its_serial_id_hex, NULL));
	ASSERT_EQ(idata.GetItsPrefixId(), std::string(its_prefix_id));
	ASSERT_EQ(idata.GetItsSerialId(), str2oct(its_serial_id_hex));
	ASSERT_EQ(idata.GetItsCanonicalId(), cid);
	ASSERT_FALSE(idata.IsGenerateItsSerialId());

	ASSERT_TRUE(idata.SetItsCanonicalID(empty, its_prefix_id, std::string("generate"), NULL));
	ASSERT_EQ(idata.GetItsPrefixId(), std::string(its_prefix_id));
	ASSERT_TRUE(idata.IsGenerateItsSerialId());

	void *t_key = ECKey_ReadPrivateKeyB64(its_tkey);
	ASSERT_TRUE(t_key != NULL);
	ASSERT_TRUE(idata.SetItsCanonicalID(empty, its_prefix_id, std::string("generate"), t_key));
	ASSERT_EQ(idata.GetItsPrefixId(), std::string(its_prefix_id));
	ASSERT_EQ(idata.GetItsSerialId(), str2oct(its_tkey_pubkey_id.c_str()));
	ASSERT_FALSE(idata.IsGenerateItsSerialId());
}


TEST(its_enrollment_ec_request, add)
{
	ItsPkiCmdArguments cmd_args;
	defaultCmdArgs(cmd_args);

	ItsPkiInternalData idata;
	
	ASSERT_TRUE(ParseEcEnrollmentCmdArguments(cmd_args, idata));
	ItsPkiSession session(idata);
	idata.SetItsEcCertValidFrom(ec_inner_request_cert_valid_from);
	idata.SetItsEcCertDuration(3, IEEE1609dot2BaseTypes::Duration::ALT_years);

        EtsiTs102941TypesEnrolment::InnerEcRequest ec_inner_request;
	OCTETSTRING ec_inner_request_encoded;
	ASSERT_TRUE(session.EcEnrollmentRequest_InnerEcRequest(idata, ec_inner_request));
	ASSERT_TRUE(encInnerEcRequest(ec_inner_request, ec_inner_request_encoded));
	std::cout << "ec_inner_request_encoded: " << oct2str(ec_inner_request_encoded) << std::endl;
	ASSERT_EQ(ec_inner_request_encoded, str2oct(blob_ec_inner_request));

	OCTETSTRING ec_enrollment_request;
        ASSERT_TRUE(session.EcEnrollmentRequest_Create(idata, ec_enrollment_request));

	void *prvkey = ECKey_ReadPrivateKeyB64(ea_eprvkey);
	ASSERT_TRUE(session.EcEnrollmentRequest_Parse(ec_enrollment_request, prvkey, ec_inner_request));
	
	ec_inner_request_encoded.clean_up();
	ASSERT_TRUE(encInnerEcRequest(ec_inner_request, ec_inner_request_encoded));
	ASSERT_EQ(ec_inner_request_encoded, str2oct(blob_ec_inner_request));
	ASSERT_EQ(idata.GetItsCanonicalId(), ec_inner_request.itsId());

	ec_enrollment_request = str2oct(blob_ec_enrollment_request);
	ec_inner_request_encoded.clean_up();
	std::cout << "#### Before ####" << std::endl;
	ASSERT_TRUE(session.EcEnrollmentRequest_Parse(ec_enrollment_request, prvkey, ec_inner_request));
}


TEST(its_enrollment_ec_response, add)
{
	ItsPkiCmdArguments cmd_args;
	defaultCmdArgs(cmd_args);

	ItsPkiInternalData idata;

	ASSERT_TRUE(ParseEcEnrollmentCmdArguments(cmd_args, idata));
	idata.SetItsEcCertValidFrom(ec_inner_request_cert_valid_from);
	idata.SetItsEcCertDuration(3, IEEE1609dot2BaseTypes::Duration::ALT_years);

	ItsPkiSession session(idata);

	OCTETSTRING skey_id = str2oct(blob_ec_enrollment_response_skey_id);
	OCTETSTRING aes_key = str2oct(blob_ec_enrollment_response_aes_key);
	OCTETSTRING tag = str2oct(blob_ec_enrollment_response_tag);
	session.setSKeyContext(skey_id, aes_key, tag);

	OCTETSTRING ret_cert;
	OCTETSTRING ec_enrollment_response_encoded = str2oct(blob_ec_enrollment_response);
	ASSERT_TRUE(session.EcEnrollmentResponse_Parse(idata.GetEACertBlob(), ec_enrollment_response_encoded, ret_cert));
}


TEST(its_enrollment_at_request, add)
{
	ItsPkiCmdArguments cmd_args;
	defaultCmdArgs(cmd_args);

	ItsPkiInternalData idata;
	
	ASSERT_TRUE(ParseAtEnrollmentCmdArguments(cmd_args, idata));
	ItsPkiSession session(idata);

	OCTETSTRING request;
	ASSERT_TRUE(session.AtEnrollmentRequest_Create(idata, request));

	void *ea_prvkey = ECKey_ReadPrivateKeyB64(ea_eprvkey);
	void *aa_prvkey = ECKey_ReadPrivateKeyB64(aa_eprvkey);
	ASSERT_TRUE(session.AtEnrollmentRequest_Parse(request, ea_prvkey, aa_prvkey));
}
