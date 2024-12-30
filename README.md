# Trusted platform module (TPM) roots

The `tpm_roots` crate provides trust anchors and certification authority (CA) certificates in support of verifying
attestations from TPM-backed virtual smart cards (VSCs). The focus is on attestations presented to a Purebred portal or
Purebred-enabled certification authority (CA). Attestations may be presented to a portal during pre-enrollment or to a
CA as part of a SCEP request. 

The certificates included in this crate are assumed to have been obtained per the instructions [here](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates)
with the resulting manually verified `TrustedTpm.cab` file placed at the root of this crate. A build script processes
the CAB file to prepare the artifacts used by the functional interface of the crate. The build script will attempt to 
download an updated file, and if one is found, validate it, save it to the repo and use it for building. CAB verification 
is performed via the `tpm_cab_verify` crate. Certificates from the CAB file that cannot be validated will be discarded
with a log message emitted.

## Features

Two features are defined to enable builds to feature certificates that would otherwise be discarded due to validation errors.

`unverified_amd_roots` will cause inclusion of an AMD engineering root that is not included in the CAB file and was obtained
from an http URI indicated in an authorityInfoAccess extension.

`sha1_certs` will cause a signature verification function that supports RSA with SHA-1 signatures when processing CAB contents.

## Known issues

Using a CAB file from December 24, 2024, the following errors were observed when attempting to verify intermediate CA
certificates during building. Some can be addressed using features. Others will remain unaddressed until the `certval`
crate is updated to address the issue.

### AMD

The CAB file contains thirty-six AMD intermediate CA certificates for which no certification paths can be built using the
contents of the CAB file. While the certificates feature an AIA extension, the certificate retrieved from the referenced
URLs are self-signed and cannot be used to build and verify a certification path. Were the certificates available via a
trustworthy mechanism, the paths would all validate.

```text
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-AERFamily-6A668AE95CA8508559C3E1D872F2417D.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-CRDFamily-5B401A1127EA54E3685B06D275FE8399.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-GNFamily-403113170A425ABD6B04CE6BF21FD467.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-GNRFamily-842A9A2652E452CC63DBD8FA9C218ED4.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-HPTFamily-F21A726D76AF588151CA619A0596D812.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-MDNFamily-87A9580E58935BBD40616CCF1820BEEF.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-PHX2Family-3887D9A52A04517246E45296FF1E2F8E.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-PHXFamily-3411EF15082F59EC465D7DEC188BB0A1.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-RMBFamily-D30EE6F7557055BA66AD1A1DD1157D2C.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-RPLFamily-5B8502F0A93A5B6E50D659FED374CF19.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-STPFamily-DE88506F89845CC24D912DBA442CADCD.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-STXFamily-7C4760BD7AC95E2F5336A9D6028B1E10.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-STXHFamily-841ED9E18F875F705AFACAD1CEFAFE37.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-RNFamily.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-RVFamily.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-SSPFamily.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-AERFamily-CCB96594EB1D57D7560EFB6022F67275.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-CRDFamily-B7F5D6F2A3165E235FD1FFBE69F2BFA9.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-GNFamily-639A786220D457236F8C816E1555F565.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-GNRFamily-FE5429C191BE55C2613A0F7DC3360E89.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-HPTFamily-0B7F833A00D15BEB46BA18CCE36E0244.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-MDNFamily-D053AFB18A3059D86723CD7D018489D2.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-PHX2Family-D63C16CBD4705E5B5C91095FD728772B.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-PHXFamily-A993351137005452447E60D15764141E.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-RMBFamily-51ADE34A2F8253525E2321AD63F7B197.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-RPLFamily-1E34E7EF9C15FA479A9F398BC865D60.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-STPFamily-E66DF8C15E99581D7EEFA04D9ECE369A.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-STXFamily-AC721D42534F54F84DBA160B17E1C920.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-STXHFamily-f9afd54db71d51bc482ed80e4a118f62.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-RNFamily.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-RVFamily.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-SSPFamily.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-KRKFamily-ACEB8D2B409157C74EB2EE08CED9B645.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-SHPFamily-EB7F6EC0482058DC50691212B414464A.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-KRKFamily-C1C1ED276EC755E277AD88C79AAE8EE7.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-SHPFamily-56994D25E17B5ED968FDD36ABD64804E.crt. Ignoring and continuing.
```

### Infineon

The CAB file features thirty-five certificates signed using SHA-1 with RSA. By default, the `certval` crate does not support
verifying SHA-1 with RSA signatures.

```text
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_01.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_02.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_03.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_04.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_05.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_06.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_07.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_08.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_10.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_11.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_12.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_13.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_14.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_15.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_16.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_17.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_18.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_19.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_20.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_21.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_22.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_23.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_25.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_26.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_27.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_28.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_29.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_31.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_32.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_33.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_37.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_39.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_53.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_55.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\IFX_TPM_EK_Intermediate_CA_63.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
```

Six were due to use of the ecdsa-with-SHA512 algorithm, which is not currently supported in the `certval` crate.

```text
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\Infineon_OPTIGA(TM)_TPM_2.0_ECC_CA_054.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\Infineon_OPTIGA(TM)_TPM_2.0_ECC_CA_056.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\OptigaEccMfrCA052.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\OptigaEccMfrCA053.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\OptigaEccMfrCA061.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\OptigaEccMfrCA064.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\OptigaEccMfrCA065.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\OptigaEccMfrCA067.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
```

### Microsoft

The CAB file features fifty-one Microsoft certificates for which no valid certification paths can be built using the contents of the CAB file.
These certificates were all expired by the date the CAB file was obtained.

```text
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-0d9969519b979d32ee4b803165664e9cc86f9d0d.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-18b1af70b93f991972f362556a9a3fbf4bb24e0d.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-2a77a0e342cbc6c72ee3fafc3b0a7bcea7c9ce4e.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-2f572bbadec4d18e0d91ff4375fb468c61b8c7af.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-347c93cabded6168c61fdc8740a7353e46751616.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-37ae346baa54c513cff0290bb321a22a34a4a8c4.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-46f26f96330691e561b72f7a63dce3a0517039fb.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-5d0815951f5f60638a69e7252f3ec4becd7554b2.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-7cb4b78e688614be4421c5858f15b96d5eab51ee.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-8343bac2129d78299c4b513cc3de61037bfcc955.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-IFX-KEYID-97E5D1CD8B0497C04B4655A869C8F30EFA89388D.CER. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-9c7df5a91c3d49bbe7378d4aba12ff8e78a2d75c.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-a26ceeac95fa33673219d0c2a77637102fb53ff2.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ifx-keyid-ce77153b6e110ca4ae2971a09851ef499326202a.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-intc-keyid-17a00575d05e58e3881210bb98b1045bb4c30639.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ntc-keyid-23f4e22ad3be374a449772954aa283aed752572e.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\EUS-ntc-keyid-882f047b87121cf9885f31160bc7bb5586af471b.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-0d9969519b979d32ee4b803165664e9cc86f9d0d.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-18b1af70b93f991972f362556a9a3fbf4bb24e0d.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-2a77a0e342cbc6c72ee3fafc3b0a7bcea7c9ce4e.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-2f572bbadec4d18e0d91ff4375fb468c61b8c7af.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-347c93cabded6168c61fdc8740a7353e46751616.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-37ae346baa54c513cff0290bb321a22a34a4a8c4.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-46f26f96330691e561b72f7a63dce3a0517039fb.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-5d0815951f5f60638a69e7252f3ec4becd7554b2.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-7cb4b78e688614be4421c5858f15b96d5eab51ee.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-8343bac2129d78299c4b513cc3de61037bfcc955.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-IFX-KEYID-97E5D1CD8B0497C04B4655A869C8F30EFA89388D.CER. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-9c7df5a91c3d49bbe7378d4aba12ff8e78a2d75c.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-a26ceeac95fa33673219d0c2a77637102fb53ff2.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ifx-keyid-ce77153b6e110ca4ae2971a09851ef499326202a.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-intc-keyid-17a00575d05e58e3881210bb98b1045bb4c30639.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ntc-keyid-23f4e22ad3be374a449772954aa283aed752572e.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\NCU-ntc-keyid-882f047b87121cf9885f31160bc7bb5586af471b.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-0d9969519b979d32ee4b803165664e9cc86f9d0d.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-18b1af70b93f991972f362556a9a3fbf4bb24e0d.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-2a77a0e342cbc6c72ee3fafc3b0a7bcea7c9ce4e.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-2f572bbadec4d18e0d91ff4375fb468c61b8c7af.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-347c93cabded6168c61fdc8740a7353e46751616.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-37ae346baa54c513cff0290bb321a22a34a4a8c4.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-46f26f96330691e561b72f7a63dce3a0517039fb.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-5d0815951f5f60638a69e7252f3ec4becd7554b2.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-7cb4b78e688614be4421c5858f15b96d5eab51ee.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-8343bac2129d78299c4b513cc3de61037bfcc955.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-IFX-KEYID-97E5D1CD8B0497C04B4655A869C8F30EFA89388D.CER. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-9c7df5a91c3d49bbe7378d4aba12ff8e78a2d75c.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-a26ceeac95fa33673219d0c2a77637102fb53ff2.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ifx-keyid-ce77153b6e110ca4ae2971a09851ef499326202a.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-intc-keyid-17a00575d05e58e3881210bb98b1045bb4c30639.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ntc-keyid-23f4e22ad3be374a449772954aa283aed752572e.cer. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from Microsoft\IntermediateCA\WUS-ntc-keyid-882f047b87121cf9885f31160bc7bb5586af471b.cer. Ignoring and continuing.
```

### Nation Z

The CAB file features ten Nation Z certificates for which no valid certification paths can be built using the contents of the CAB file.
All were due to use of the ecdsa-with-SHA512 algorithm, which is not currently supported in the `certval` crate.

```text
warning: tpm_roots@0.1.0: failed to validate certificate from NationZ\IntermediateCA\NSEccEkCA001.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from NationZ\IntermediateCA\NSEccEkCA002.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from NationZ\IntermediateCA\NSEccEkCA003.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from NationZ\IntermediateCA\NSEccEkCA004.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from NationZ\IntermediateCA\NSEccEkCA005.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from NationZ\IntermediateCA\NSTPMEccEkCA001.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from NationZ\IntermediateCA\NSTPMEccEkCA002.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from NationZ\IntermediateCA\NSTPMEccEkCA003.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from NationZ\IntermediateCA\NSTPMEccEkCA004.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from NationZ\IntermediateCA\NSTPMEccEkCA005.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
```
