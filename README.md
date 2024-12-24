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

The CAB file contains four AMD intermediate CA certificates for which no valid certification paths can be built using the contents of the CAB file.

```text
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-KRKFamily-ACEB8D2B409157C74EB2EE08CED9B645.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-ECC-ICA-SHPFamily-EB7F6EC0482058DC50691212B414464A.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-KRKFamily-C1C1ED276EC755E277AD88C79AAE8EE7.crt. Ignoring and continuing.
warning: tpm_roots@0.1.0: failed to find any certification paths for certificate from AMD\IntermediateCA\AMD-fTPM-RSA-ICA-SHPFamily-56994D25E17B5ED968FDD36ABD64804E.crt. Ignoring and continuing.
```

### Infineon

The CAB file contains two Infineon intermediate CA certificates for which no valid certification paths can be built using the contents of the CAB file.

```text
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\OptigaEccMfrCA065.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
warning: tpm_roots@0.1.0: failed to validate certificate from Infineon\IntermediateCA\OptigaEccMfrCA067.crt. Ignoring and continuing. Error: [PathValidation(SignatureVerificationFailure)]
```

### Microsoft

The CAB file features fifty-one Microsoft certificates for which no valid certification paths can be built using the contents of the CAB file.

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
