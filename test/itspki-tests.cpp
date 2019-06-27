#include "gtest/gtest.h"
#include "itspki-cmd-args.hh"
#include "its/itspki-internal-data.hh"
#include "its/itspki-work.hh"

const char *its_tkey =    "MHcCAQEEIGjdbEK4O35mcWTsC7LhY/YoZdZINpu16Zm3JQQVZb7CoAoGCCqGSM49AwEHoUQDQgAE5vxO9sNaJqWdkBj19TWHY0yWwRHvPxiWTxjQEEIRS07b8uA3mCmkWg8blGwa2uItzd5Djdgpxjwv3TWVaedxoA==";
const char *its_ec_vkey = "MHcCAQEEIGjdbEK4O35mcWTsC7LhY/YoZdZINpu16Zm3JQQVZb7CoAoGCCqGSM49AwEHoUQDQgAE5vxO9sNaJqWdkBj19TWHY0yWwRHvPxiWTxjQEEIRS07b8uA3mCmkWg8blGwa2uItzd5Djdgpxjwv3TWVaedxoA==";
const char *its_ec_ekey = "MHcCAQEEIGjdbEK4O35mcWTsC7LhY/YoZdZINpu16Zm3JQQVZb7CoAoGCCqGSM49AwEHoUQDQgAE5vxO9sNaJqWdkBj19TWHY0yWwRHvPxiWTxjQEEIRS07b8uA3mCmkWg8blGwa2uItzd5Djdgpxjwv3TWVaedxoA==";
const char *ea_cert = "gAMAgEJI3Vtd8DQ7GYEPVVRPUElBX1RFU1RfRUExAAAAAAAcaAP1hgAFAQGAAgJvgQMCAQ4BAaCAAQiAASSCCAMB//wD/wADgAElggoEAf///wT/AAAAgAGJggYCAeAC/x+AAYqCBgIBwAL/P4ABi4IOBgGUAAD/+Ab/AAAAAAeAAYyCCgQB///gBP8AAB+AAY2CBAEAAf+AAgJvggYCAcAC/z8BAsAAgIM1LJ4tKr0xTF+JvyQ2VveGsGC9Y5sk7nVWAUV4WnOqvYCBg4FkhxryzyZC0LhFAPQLS0HTL/hkr9AQpFpum9Ijnh7vgmGAEGN8z7U89CM55+ZmAV1Da1/mTxTATVG0otBxh3eCq+r6RN6vs4gHXCPGNot6jdn5GxhH+hgt38bOyBThgikQO21t31n1yr9Lo6U8EMvCpcrZf6ERUIIPqrY/CfpWlVvs";
const char *aa_cert = "gAMAgEJI3Vtd8DQ7GYEPVVRPUElBX1RFU1RfQUExAAAAAAAcaAP1hgAFAQGAAgJvgQMCATIBAaCAAQeAASSCCAMB//wD/wADgAElggoEAf///wT/AAAAgAGJggYCAeAC/x+AAYqCBgIBwAL/P4ABi4IOBgGUAAD/+Ab/AAAAAAeAAYyCCgQB///gBP8AAB+AAY2CBAEAAf8BAsAAgIJMVUp2x5WNacXWRpvKchhjsd1yP92YgzWDn12PETgY7YCAglNasR1KApOsr5xX3kyeek2eDbKzzd7M5+SxcSn/I/5FgmGAV9vbLo+GyAgKndOwwOWAlGWUxtqzAJe7gLTLheTaqdR7puulu+wB6/L7hvUJPAnDFDfL/RYlTGpE0lZN3rzqQBTUN3fe1jlB7AvglB4Fwun16QJ4X/I8+7jcFRiJWBQM";
const char *canonical_id = "TEST-DEMO-51AC321296526271";
long app_perms_psid = 623;
const char *ssp_bitmap = "01C0";

bool ParseEcEnrollmentCmdArguments(ItsPkiCmdArguments cmd_args, ItsPkiInternalData &idata);


TEST(itspki_encode, add)
{
	ItsPkiCmdArguments cmd_args;

	cmd_args.its_tkey_b64 = std::string(its_tkey);
	cmd_args.its_ec_vkey_b64 = std::string(its_ec_vkey);
	cmd_args.its_ec_ekey_b64 = std::string(its_ec_ekey);
	cmd_args.eacert_b64 = std::string(ea_cert);
	cmd_args.aacert_b64 = std::string(aa_cert);
	cmd_args.its_ec_ekey_enable = true;
	cmd_args.its_canonical_id = std::string(canonical_id); 
	cmd_args.app_perms_psid  = app_perms_psid; 
	cmd_args.app_perms_ssp_bitmap = std::string(ssp_bitmap); 

	ItsPkiInternalData idata;
	ASSERT_TRUE(ParseEcEnrollmentCmdArguments(cmd_args, idata));
        ASSERT_TRUE(idata.CheckEcEnrollmentArguments());

	ItsPkiWork work(idata);
        OCTETSTRING data_encrypted;
	ASSERT_TRUE(work.EcEnrollmentRequest_Create(idata, data_encrypted));
}
