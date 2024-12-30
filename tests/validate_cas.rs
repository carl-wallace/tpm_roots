//! Test cases to generate a report detailing CA validation
//!
use certval::PathValidationStatus;
use log::error;
use rsa::Pkcs1v15Sign;
use rsa::RsaPublicKey;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::path::Path;
use std::{ffi::OsStr, fs, io::BufRead};

use walkdir::WalkDir;

use base64ct::{Base64, Encoding};

use certval::{
    buffer_to_hex, CertFile, CertSource, CertVector, CertificationPath, CertificationPathResults,
    CertificationPathSettings, Error, PDVCertificate, PkiEnvironment, TaSource,
};
use rsa::pkcs8::DecodePublicKey;
use x509_cert::der::oid::db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION;
use x509_cert::der::Encode;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// Handle PEM files that do not adhere to strict line length limits
#[cfg(test)]
fn decode_broken_pem(bad_pem: &[u8]) -> certval::Result<Vec<u8>> {
    let mut b64 = String::with_capacity(bad_pem.len());
    for line in bad_pem.lines() {
        if let Ok(line) = line {
            if line.chars().nth(0).unwrap_or_default() != '-' {
                b64 += line.trim();
            }
        }
    }

    match Base64::decode_vec(&b64) {
        Ok(v) => Ok(v),
        Err(_e) => Err(certval::Error::ParseError),
    }
}

/// Parse a cert whether its PEM (broken or standards-compliant) or DER
#[cfg(test)]
fn parse_cert(buf: &[u8]) -> certval::Result<PDVCertificate> {
    let buf = if buf[0] != 0x30 {
        match pem_rfc7468::decode_vec(&buf) {
            Ok(b) => b.1,
            Err(_e) => {
                if let Ok(b) = decode_broken_pem(&buf) {
                    b
                } else {
                    return Err(Error::ParseError);
                }
            }
        }
    } else {
        buf.to_vec()
    };
    Ok(PDVCertificate::try_from(buf.as_slice())?)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
enum ValidationResults {
    NotAttempted,
    Verified,
    VerifiedWithoutRevocation,
    VerifiedWithModifiedEnvironment,
    VerifiedWithModifiedEnvironmentWithoutRevocation,
    FailedToVerify,
    NoPathsFound,
}

#[cfg(test)]
impl crate::ValidationResults {
    fn successfully_verified(&self) -> bool {
        match self {
            ValidationResults::NotAttempted => false,
            ValidationResults::Verified => true,
            ValidationResults::VerifiedWithoutRevocation => true,
            ValidationResults::VerifiedWithModifiedEnvironment => true,
            ValidationResults::VerifiedWithModifiedEnvironmentWithoutRevocation => true,
            ValidationResults::FailedToVerify => false,
            ValidationResults::NoPathsFound => false,
        }
    }
}

#[cfg(test)]
struct ValidationInstructions {
    pub targets: BTreeMap<String, ValidationResults>,
    pub pe: PkiEnvironment,
    pub cps: CertificationPathSettings,
    pub additional_tas: Vec<Vec<u8>>,
    pub skip_revocation: bool,
    pub accept_sha1_certs: bool,
}

#[cfg(test)]
impl ValidationInstructions {
    fn verified(&self) -> ValidationResults {
        if self.skip_revocation && (self.accept_sha1_certs || !self.additional_tas.is_empty()) {
            ValidationResults::VerifiedWithModifiedEnvironmentWithoutRevocation
        } else if self.skip_revocation {
            ValidationResults::VerifiedWithoutRevocation
        } else if self.accept_sha1_certs || !self.additional_tas.is_empty() {
            ValidationResults::VerifiedWithModifiedEnvironment
        } else {
            ValidationResults::Verified
        }
    }

    fn all_verified(&self, known_issues: &[&str]) -> bool {
        for target in &self.targets {
            let trimmed_target = target.0.replace("tests/examples/TrustedTPM/", "");
            if !target.1.successfully_verified() && !known_issues.contains(&trimmed_target.as_str())
            {
                return false;
            }
        }
        true
    }

    fn new(folder: &str) -> Self {
        let mut targets: BTreeMap<String, ValidationResults> = BTreeMap::new();
        for entry in WalkDir::new(folder) {
            match entry {
                Ok(entry) => {
                    let path = entry.path();
                    if entry.file_type().is_dir() {
                        continue;
                    } else {
                        let filename = match path.to_str() {
                            Some(filename) => filename,
                            None => continue,
                        };
                        if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                            if !["der", "crt", "cer"].contains(&ext) {
                                continue;
                            }
                        }
                        targets.insert(filename.to_string(), ValidationResults::NotAttempted);
                    }
                }
                Err(e) => {
                    println!("Failed to traverse directory: {e:?}");
                }
            }
        }

        ValidationInstructions {
            targets,
            pe: Default::default(),
            cps: Default::default(),
            additional_tas: vec![],
            skip_revocation: false,
            accept_sha1_certs: false,
        }
    }

    /// Prepare a PkiEnvironment using the ta.cbor and ca.cbor resources with optional additional TAs added.
    #[cfg(test)]
    fn prepare_environment(&mut self) -> certval::Result<()> {
        self.pe = PkiEnvironment::default();
        self.pe.populate_5280_pki_environment();

        self.cps = CertificationPathSettings::default();
        if self.skip_revocation {
            self.cps.set_check_revocation_status(false);
        } else {
            self.cps.set_check_revocation_status(true);
        }

        if self.accept_sha1_certs {
            self.pe
                .add_verify_signature_message_callback(verify_signature_message_rust_crypto_sha1);
        }

        let ta_cbor = include_bytes!("../ta.cbor");
        let ca_cbor = include_bytes!("../ca.cbor");
        let mut ta_source = TaSource::new_from_cbor(ta_cbor)?;

        for (ii, ta_buf) in self.additional_tas.iter().enumerate() {
            let cf = CertFile {
                filename: format!("TA #{ii}"),
                bytes: ta_buf.to_vec(),
            };
            ta_source.push(cf);
        }

        let mut cert_source = CertSource::new_from_cbor(ca_cbor)?;
        cert_source.initialize(&self.cps)?;
        ta_source.initialize()?;

        self.pe.add_trust_anchor_source(Box::new(ta_source));
        self.pe.add_certificate_source(Box::new(cert_source));
        Ok(())
    }
}

/// Prepare a PkiEnvironment using the ta.cbor and ca.cbor resources with optional additional TAs added.
#[cfg(test)]
async fn validate_intermediate_cas(
    vi: &mut ValidationInstructions,
    known_issues: &[&str],
) -> certval::Result<()> {
    vi.prepare_environment()?;

    let verification_status = vi.verified();
    for target in &mut vi.targets.iter_mut() {
        if target.1.successfully_verified() {
            continue;
        }

        let filename = target.0;
        let data: Vec<u8> = fs::read(filename).unwrap();
        let cert = match parse_cert(data.as_slice()) {
            Ok(cert) => cert,
            Err(e) => {
                if !known_issues
                    .contains(&filename.replace("tests/examples/TrustedTPM/", "").as_str())
                {
                    println!("Failed to parse certificate from {filename}. Ignoring and continuing. Error: {e:?}.");
                }
                continue;
            }
        };
        let mut errors = vec![];
        let mut paths: Vec<CertificationPath> = vec![];

        if vi
            .pe
            .get_paths_for_target(&cert, &mut paths, 0, vi.cps.get_time_of_interest())
            .is_ok()
        {
            if paths.is_empty() {
                *target.1 = ValidationResults::NoPathsFound;
                continue;
            } else {
                for path in paths.iter_mut() {
                    let mut cpr = CertificationPathResults::new();
                    match vi.pe.validate_path(&vi.pe, &vi.cps, path, &mut cpr) {
                        Ok(_) => {
                            *target.1 = verification_status.clone();
                            break;
                        }
                        Err(e) => {
                            *target.1 = ValidationResults::FailedToVerify;
                            errors.push(e);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
async fn common_cases(folder: &str, known_issues: &[&str]) {
    let mut vi = ValidationInstructions::new(folder);
    validate_intermediate_cas(&mut vi, known_issues)
        .await
        .unwrap();

    if !vi.all_verified(&[]) {
        vi.skip_revocation = true;
        validate_intermediate_cas(&mut vi, known_issues)
            .await
            .unwrap();
    }

    let mut v = Vec::from_iter(&vi.targets);
    v.sort_by(|&(_, a), &(_, b)| b.cmp(&a));
    for target in v {
        println!(
            "{}: {:?}",
            target.0.replace("tests/examples/TrustedTPM/", ""),
            target.1
        );
    }
    assert!(vi.all_verified(&known_issues));
    if !known_issues.is_empty() {
        println!(
            "{} known issues that have no current remedy",
            known_issues.len()
        );
    }
}
#[tokio::test]
async fn validate_cas_amd() {
    let known_issues = [
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-AERFamily-6A668AE95CA8508559C3E1D872F2417D.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-CRDFamily-5B401A1127EA54E3685B06D275FE8399.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-GNFamily-403113170A425ABD6B04CE6BF21FD467.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-GNRFamily-842A9A2652E452CC63DBD8FA9C218ED4.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-HPTFamily-F21A726D76AF588151CA619A0596D812.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-MDNFamily-87A9580E58935BBD40616CCF1820BEEF.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-PHX2Family-3887D9A52A04517246E45296FF1E2F8E.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-PHXFamily-3411EF15082F59EC465D7DEC188BB0A1.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-RMBFamily-D30EE6F7557055BA66AD1A1DD1157D2C.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-RPLFamily-5B8502F0A93A5B6E50D659FED374CF19.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-STPFamily-DE88506F89845CC24D912DBA442CADCD.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-STXFamily-7C4760BD7AC95E2F5336A9D6028B1E10.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-ICA-STXHFamily-841ED9E18F875F705AFACAD1CEFAFE37.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-RNFamily.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-RVFamily.crt",
        "AMD/IntermediateCA/AMD-fTPM-ECC-SSPFamily.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-AERFamily-CCB96594EB1D57D7560EFB6022F67275.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-CRDFamily-B7F5D6F2A3165E235FD1FFBE69F2BFA9.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-GNFamily-639A786220D457236F8C816E1555F565.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-GNRFamily-FE5429C191BE55C2613A0F7DC3360E89.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-HPTFamily-0B7F833A00D15BEB46BA18CCE36E0244.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-MDNFamily-D053AFB18A3059D86723CD7D018489D2.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-PHX2Family-D63C16CBD4705E5B5C91095FD728772B.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-PHXFamily-A993351137005452447E60D15764141E.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-RMBFamily-51ADE34A2F8253525E2321AD63F7B197.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-RPLFamily-1E34E7EF9C15FA479A9F398BC865D60.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-STPFamily-E66DF8C15E99581D7EEFA04D9ECE369A.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-STXFamily-AC721D42534F54F84DBA160B17E1C920.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-ICA-STXHFamily-f9afd54db71d51bc482ed80e4a118f62.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-RNFamily.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-RVFamily.crt",
        "AMD/IntermediateCA/AMD-fTPM-RSA-SSPFamily.crt",
    ];
    let mut vi = ValidationInstructions::new("tests/examples/TrustedTPM/AMD/IntermediateCA");
    validate_intermediate_cas(&mut vi, &known_issues)
        .await
        .unwrap();

    if !vi.all_verified(&[]) {
        vi.skip_revocation = true;
        validate_intermediate_cas(&mut vi, &known_issues)
            .await
            .unwrap();
    }

    if !vi.all_verified(&[]) {
        let amd_eng_root = include_bytes!("examples/23452201D41C5AB064032BD23F158FEF.crt").to_vec();
        let amd_eng_root2 =
            include_bytes!("examples/264D39A23CEB5D5B49D610044EEBD121.crt").to_vec();
        vi.additional_tas = vec![amd_eng_root, amd_eng_root2];
        vi.skip_revocation = false;
        validate_intermediate_cas(&mut vi, &known_issues)
            .await
            .unwrap();
    }

    if !vi.all_verified(&[]) {
        vi.skip_revocation = true;
        validate_intermediate_cas(&mut vi, &known_issues)
            .await
            .unwrap();
    }

    let mut v = Vec::from_iter(&vi.targets);
    v.sort_by(|&(_, a), &(_, b)| b.cmp(&a));
    for target in v {
        println!(
            "{}: {:?}",
            target.0.replace("tests/examples/TrustedTPM/", ""),
            target.1
        );
    }
    assert!(vi.all_verified(&[]));
    println!(
        "{} known issues that can be addressed using unverified_amd_root feature",
        known_issues.len()
    );
}

#[tokio::test]
async fn validate_cas_infineon() {
    let known_issues = [
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_01.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_02.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_03.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_04.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_05.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_06.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_07.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_08.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_10.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_11.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_12.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_13.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_14.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_15.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_16.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_17.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_18.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_19.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_20.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_21.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_22.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_23.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_25.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_26.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_27.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_28.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_29.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_31.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_32.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_33.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_37.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_39.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_53.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_55.crt",
        "Infineon/IntermediateCA/IFX_TPM_EK_Intermediate_CA_63.crt",
        "Infineon/IntermediateCA/Infineon_OPTIGA(TM)_TPM_2.0_ECC_CA_054.crt",
        "Infineon/IntermediateCA/Infineon_OPTIGA(TM)_TPM_2.0_ECC_CA_056.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA052.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA053.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA061.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA064.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA065.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA067.crt",
    ];

    let residual_issues = [
        "Infineon/IntermediateCA/Infineon_OPTIGA(TM)_TPM_2.0_ECC_CA_054.crt",
        "Infineon/IntermediateCA/Infineon_OPTIGA(TM)_TPM_2.0_ECC_CA_056.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA052.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA053.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA061.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA064.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA065.crt",
        "Infineon/IntermediateCA/OptigaEccMfrCA067.crt",
    ];

    let mut vi = ValidationInstructions::new("tests/examples/TrustedTPM/Infineon/IntermediateCA");
    validate_intermediate_cas(&mut vi, &known_issues)
        .await
        .unwrap();

    if !vi.all_verified(&[]) {
        vi.skip_revocation = true;
        validate_intermediate_cas(&mut vi, &known_issues)
            .await
            .unwrap();
    }

    if !vi.all_verified(&[]) {
        vi.skip_revocation = false;
        vi.accept_sha1_certs = true;
        validate_intermediate_cas(&mut vi, &known_issues)
            .await
            .unwrap();
    }

    if !vi.all_verified(&[]) {
        vi.skip_revocation = true;
        validate_intermediate_cas(&mut vi, &known_issues)
            .await
            .unwrap();
    }

    let mut v = Vec::from_iter(&vi.targets);
    v.sort_by(|&(_, a), &(_, b)| b.cmp(&a));
    for target in v {
        println!(
            "{}: {:?}",
            target.0.replace("tests/examples/TrustedTPM/", ""),
            target.1
        );
    }
    assert!(vi.all_verified(&residual_issues));
    println!("{} known issues that can be verified with sha1_certs feature and {} that have no current remedy", known_issues.len(), residual_issues.len());
}

#[tokio::test]
async fn validate_cas_atmel() {
    common_cases("tests/examples/TrustedTPM/Atmel/IntermediateCA", &[]).await;
}

#[tokio::test]
async fn validate_cas_intel() {
    common_cases("tests/examples/TrustedTPM/intel/IntermediateCA", &[]).await;
}

#[tokio::test]
async fn validate_cas_microsoft() {
    let known_issues = [
        "microsoft/IntermediateCA/EUS-ifx-keyid-0d9969519b979d32ee4b803165664e9cc86f9d0d.cer",
        "microsoft/IntermediateCA/EUS-ifx-keyid-18b1af70b93f991972f362556a9a3fbf4bb24e0d.cer",
        "microsoft/IntermediateCA/EUS-ifx-keyid-2a77a0e342cbc6c72ee3fafc3b0a7bcea7c9ce4e.cer",
        "microsoft/IntermediateCA/EUS-ifx-keyid-2f572bbadec4d18e0d91ff4375fb468c61b8c7af.cer",
        "microsoft/IntermediateCA/EUS-ifx-keyid-347c93cabded6168c61fdc8740a7353e46751616.cer",
        "microsoft/IntermediateCA/EUS-ifx-keyid-37ae346baa54c513cff0290bb321a22a34a4a8c4.cer",
        "microsoft/IntermediateCA/EUS-ifx-keyid-46f26f96330691e561b72f7a63dce3a0517039fb.cer",
        "microsoft/IntermediateCA/EUS-ifx-keyid-5d0815951f5f60638a69e7252f3ec4becd7554b2.cer",
        "microsoft/IntermediateCA/EUS-ifx-keyid-7cb4b78e688614be4421c5858f15b96d5eab51ee.cer",
        "microsoft/IntermediateCA/EUS-ifx-keyid-8343bac2129d78299c4b513cc3de61037bfcc955.cer",
        "microsoft/IntermediateCA/EUS-IFX-KEYID-97E5D1CD8B0497C04B4655A869C8F30EFA89388D.CER",
        "microsoft/IntermediateCA/EUS-ifx-keyid-9c7df5a91c3d49bbe7378d4aba12ff8e78a2d75c.cer",
        "microsoft/IntermediateCA/EUS-ifx-keyid-a26ceeac95fa33673219d0c2a77637102fb53ff2.cer",
        "microsoft/IntermediateCA/EUS-ifx-keyid-ce77153b6e110ca4ae2971a09851ef499326202a.cer",
        "microsoft/IntermediateCA/EUS-intc-keyid-17a00575d05e58e3881210bb98b1045bb4c30639.cer",
        "microsoft/IntermediateCA/EUS-ntc-keyid-23f4e22ad3be374a449772954aa283aed752572e.cer",
        "microsoft/IntermediateCA/EUS-ntc-keyid-882f047b87121cf9885f31160bc7bb5586af471b.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-0d9969519b979d32ee4b803165664e9cc86f9d0d.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-18b1af70b93f991972f362556a9a3fbf4bb24e0d.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-2a77a0e342cbc6c72ee3fafc3b0a7bcea7c9ce4e.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-2f572bbadec4d18e0d91ff4375fb468c61b8c7af.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-347c93cabded6168c61fdc8740a7353e46751616.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-37ae346baa54c513cff0290bb321a22a34a4a8c4.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-46f26f96330691e561b72f7a63dce3a0517039fb.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-5d0815951f5f60638a69e7252f3ec4becd7554b2.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-7cb4b78e688614be4421c5858f15b96d5eab51ee.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-8343bac2129d78299c4b513cc3de61037bfcc955.cer",
        "microsoft/IntermediateCA/NCU-IFX-KEYID-97E5D1CD8B0497C04B4655A869C8F30EFA89388D.CER",
        "microsoft/IntermediateCA/NCU-ifx-keyid-9c7df5a91c3d49bbe7378d4aba12ff8e78a2d75c.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-a26ceeac95fa33673219d0c2a77637102fb53ff2.cer",
        "microsoft/IntermediateCA/NCU-ifx-keyid-ce77153b6e110ca4ae2971a09851ef499326202a.cer",
        "microsoft/IntermediateCA/NCU-intc-keyid-17a00575d05e58e3881210bb98b1045bb4c30639.cer",
        "microsoft/IntermediateCA/NCU-ntc-keyid-23f4e22ad3be374a449772954aa283aed752572e.cer",
        "microsoft/IntermediateCA/NCU-ntc-keyid-882f047b87121cf9885f31160bc7bb5586af471b.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-0d9969519b979d32ee4b803165664e9cc86f9d0d.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-18b1af70b93f991972f362556a9a3fbf4bb24e0d.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-2a77a0e342cbc6c72ee3fafc3b0a7bcea7c9ce4e.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-2f572bbadec4d18e0d91ff4375fb468c61b8c7af.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-347c93cabded6168c61fdc8740a7353e46751616.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-37ae346baa54c513cff0290bb321a22a34a4a8c4.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-46f26f96330691e561b72f7a63dce3a0517039fb.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-5d0815951f5f60638a69e7252f3ec4becd7554b2.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-7cb4b78e688614be4421c5858f15b96d5eab51ee.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-8343bac2129d78299c4b513cc3de61037bfcc955.cer",
        "microsoft/IntermediateCA/WUS-IFX-KEYID-97E5D1CD8B0497C04B4655A869C8F30EFA89388D.CER",
        "microsoft/IntermediateCA/WUS-ifx-keyid-9c7df5a91c3d49bbe7378d4aba12ff8e78a2d75c.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-a26ceeac95fa33673219d0c2a77637102fb53ff2.cer",
        "microsoft/IntermediateCA/WUS-ifx-keyid-ce77153b6e110ca4ae2971a09851ef499326202a.cer",
        "microsoft/IntermediateCA/WUS-intc-keyid-17a00575d05e58e3881210bb98b1045bb4c30639.cer",
        "microsoft/IntermediateCA/WUS-ntc-keyid-23f4e22ad3be374a449772954aa283aed752572e.cer",
        "microsoft/IntermediateCA/WUS-ntc-keyid-882f047b87121cf9885f31160bc7bb5586af471b.cer",
    ];
    common_cases(
        "tests/examples/TrustedTPM/microsoft/IntermediateCA",
        &known_issues,
    )
    .await;
}

#[tokio::test]
async fn validate_cas_nationz() {
    let known_issues = [
        "NationZ/IntermediateCA/NSEccEkCA001.crt",
        "NationZ/IntermediateCA/NSEccEkCA002.crt",
        "NationZ/IntermediateCA/NSEccEkCA003.crt",
        "NationZ/IntermediateCA/NSEccEkCA004.crt",
        "NationZ/IntermediateCA/NSEccEkCA005.crt",
        "NationZ/IntermediateCA/NSTPMEccEkCA001.crt",
        "NationZ/IntermediateCA/NSTPMEccEkCA002.crt",
        "NationZ/IntermediateCA/NSTPMEccEkCA003.crt",
        "NationZ/IntermediateCA/NSTPMEccEkCA004.crt",
        "NationZ/IntermediateCA/NSTPMEccEkCA005.crt",
    ];
    common_cases(
        "tests/examples/TrustedTPM/NationZ/IntermediateCA",
        &known_issues,
    )
    .await;
}

#[tokio::test]
async fn validate_cas_nuvoton() {
    let known_issues = [
        "Nuvoton/IntermediateCA/NPCTxxxECC384LeafCA012110.cer",
        "Nuvoton/IntermediateCA/NPCTxxxECC384LeafCA012111.cer",
        "Nuvoton/IntermediateCA/NPCTxxxECC384LeafCA022110.cer",
        "Nuvoton/IntermediateCA/NPCTxxxECC384LeafCA022111.cer",
    ];
    common_cases(
        "tests/examples/TrustedTPM/Nuvoton/IntermediateCA",
        &known_issues,
    )
    .await;
}

#[tokio::test]
async fn validate_cas_qc() {
    let known_issues = ["QC/IntermediateCA/qwes_prod_ek_provisioning_intermediate.crt"];
    common_cases("tests/examples/TrustedTPM/QC/IntermediateCA", &known_issues).await;
}

#[tokio::test]
async fn validate_cas_stmicro() {
    let known_issues = [
        "STMicro/IntermediateCA/STSAFE TPM ECC384 Intermediate CA 10.crt",
        "STMicro/IntermediateCA/STSAFE TPM ECC384 Intermediate CA 11.crt",
        "STMicro/IntermediateCA/STM TPM ECC Intermediate CA 01.crt",
        "STMicro/IntermediateCA/STM TPM EK Intermediate CA 01.crt",
        "STMicro/IntermediateCA/STM TPM EK Intermediate CA 02.crt",
        "STMicro/IntermediateCA/STM TPM EK Intermediate CA 03.crt",
        "STMicro/IntermediateCA/STM TPM EK Intermediate CA 04.crt",
        "STMicro/IntermediateCA/STM TPM EK Intermediate CA 05.crt",
    ];

    common_cases(
        "tests/examples/TrustedTPM/STMicro/IntermediateCA",
        &known_issues,
    )
    .await;
}

#[test]
fn fail_on_new_folders() {
    let trusted_tpm = include_bytes!("../TrustedTpm.cab");
    let cursor = std::io::Cursor::new(trusted_tpm);
    let cabinet = match cab::Cabinet::new(cursor) {
        Ok(cabinet) => cabinet,
        Err(e) => {
            panic!("{e:?}");
        }
    };

    let expected_folders = [
        "AMD",
        "Atmel",
        "Infineon",
        "Intel",
        "Microsoft",
        "NationZ",
        "Nuvoton",
        "QC",
        "STMicro",
    ];

    let skip = ["setup.cmd", "setup.ps1", "version.txt"];

    for folder in cabinet.folder_entries() {
        for file in folder.file_entries() {
            let file_name = file.name().replace("\\", "/");
            if skip.contains(&file_name.as_str()) {
                continue;
            }

            for c in Path::new(&file_name).components() {
                if let Some(s) = c.as_os_str().to_str() {
                    if expected_folders.contains(&s) {
                        break;
                    } else {
                        panic!("{s} in an unexpected folder. Please add a unit test to validate CAs in this folder.");
                    }
                } else {
                    panic!("Failed to convert {c:?} to string");
                }
            }
        }
    }
}

#[tokio::test]
async fn fail_on_missing_known_issues() {
    // these vectors were copied from build.rs (and need to remain in sync)
    let mut known_building_issues: Vec<&str> = vec![
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-0d9969519b979d32ee4b803165664e9cc86f9d0d.cer",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-18b1af70b93f991972f362556a9a3fbf4bb24e0d.cer",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-2a77a0e342cbc6c72ee3fafc3b0a7bcea7c9ce4e.cer",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-2f572bbadec4d18e0d91ff4375fb468c61b8c7af.cer",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-347c93cabded6168c61fdc8740a7353e46751616.cer",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-37ae346baa54c513cff0290bb321a22a34a4a8c4.cer",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-46f26f96330691e561b72f7a63dce3a0517039fb.cer",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-5d0815951f5f60638a69e7252f3ec4becd7554b2.cer",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-7cb4b78e688614be4421c5858f15b96d5eab51ee.cer",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-8343bac2129d78299c4b513cc3de61037bfcc955.cer",
        "Microsoft\\IntermediateCA\\EUS-IFX-KEYID-97E5D1CD8B0497C04B4655A869C8F30EFA89388D.CER",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-9c7df5a91c3d49bbe7378d4aba12ff8e78a2d75c.cer",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-a26ceeac95fa33673219d0c2a77637102fb53ff2.cer",
        "Microsoft\\IntermediateCA\\EUS-ifx-keyid-ce77153b6e110ca4ae2971a09851ef499326202a.cer",
        "Microsoft\\IntermediateCA\\EUS-intc-keyid-17a00575d05e58e3881210bb98b1045bb4c30639.cer",
        "Microsoft\\IntermediateCA\\EUS-ntc-keyid-23f4e22ad3be374a449772954aa283aed752572e.cer",
        "Microsoft\\IntermediateCA\\EUS-ntc-keyid-882f047b87121cf9885f31160bc7bb5586af471b.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-0d9969519b979d32ee4b803165664e9cc86f9d0d.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-18b1af70b93f991972f362556a9a3fbf4bb24e0d.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-2a77a0e342cbc6c72ee3fafc3b0a7bcea7c9ce4e.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-2f572bbadec4d18e0d91ff4375fb468c61b8c7af.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-347c93cabded6168c61fdc8740a7353e46751616.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-37ae346baa54c513cff0290bb321a22a34a4a8c4.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-46f26f96330691e561b72f7a63dce3a0517039fb.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-5d0815951f5f60638a69e7252f3ec4becd7554b2.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-7cb4b78e688614be4421c5858f15b96d5eab51ee.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-8343bac2129d78299c4b513cc3de61037bfcc955.cer",
        "Microsoft\\IntermediateCA\\NCU-IFX-KEYID-97E5D1CD8B0497C04B4655A869C8F30EFA89388D.CER",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-9c7df5a91c3d49bbe7378d4aba12ff8e78a2d75c.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-a26ceeac95fa33673219d0c2a77637102fb53ff2.cer",
        "Microsoft\\IntermediateCA\\NCU-ifx-keyid-ce77153b6e110ca4ae2971a09851ef499326202a.cer",
        "Microsoft\\IntermediateCA\\NCU-intc-keyid-17a00575d05e58e3881210bb98b1045bb4c30639.cer",
        "Microsoft\\IntermediateCA\\NCU-ntc-keyid-23f4e22ad3be374a449772954aa283aed752572e.cer",
        "Microsoft\\IntermediateCA\\NCU-ntc-keyid-882f047b87121cf9885f31160bc7bb5586af471b.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-0d9969519b979d32ee4b803165664e9cc86f9d0d.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-18b1af70b93f991972f362556a9a3fbf4bb24e0d.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-2a77a0e342cbc6c72ee3fafc3b0a7bcea7c9ce4e.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-2f572bbadec4d18e0d91ff4375fb468c61b8c7af.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-347c93cabded6168c61fdc8740a7353e46751616.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-37ae346baa54c513cff0290bb321a22a34a4a8c4.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-46f26f96330691e561b72f7a63dce3a0517039fb.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-5d0815951f5f60638a69e7252f3ec4becd7554b2.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-7cb4b78e688614be4421c5858f15b96d5eab51ee.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-8343bac2129d78299c4b513cc3de61037bfcc955.cer",
        "Microsoft\\IntermediateCA\\WUS-IFX-KEYID-97E5D1CD8B0497C04B4655A869C8F30EFA89388D.CER",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-9c7df5a91c3d49bbe7378d4aba12ff8e78a2d75c.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-a26ceeac95fa33673219d0c2a77637102fb53ff2.cer",
        "Microsoft\\IntermediateCA\\WUS-ifx-keyid-ce77153b6e110ca4ae2971a09851ef499326202a.cer",
        "Microsoft\\IntermediateCA\\WUS-intc-keyid-17a00575d05e58e3881210bb98b1045bb4c30639.cer",
        "Microsoft\\IntermediateCA\\WUS-ntc-keyid-23f4e22ad3be374a449772954aa283aed752572e.cer",
        "Microsoft\\IntermediateCA\\WUS-ntc-keyid-882f047b87121cf9885f31160bc7bb5586af471b.cer",
    ];
    purge_exists(
        "tests/examples/TrustedTPM/Microsoft",
        &mut known_building_issues,
    );
    assert_eq!(0, known_building_issues.len());

    let mut known_validation_issues = vec![
        "Infineon\\IntermediateCA\\Infineon_OPTIGA(TM)_TPM_2.0_ECC_CA_054.crt",
        "Infineon\\IntermediateCA\\Infineon_OPTIGA(TM)_TPM_2.0_ECC_CA_056.crt",
        "Infineon\\IntermediateCA\\OptigaEccMfrCA052.crt",
        "Infineon\\IntermediateCA\\OptigaEccMfrCA053.crt",
        "Infineon\\IntermediateCA\\OptigaEccMfrCA061.crt",
        "Infineon\\IntermediateCA\\OptigaEccMfrCA064.crt",
        "Infineon\\IntermediateCA\\OptigaEccMfrCA065.crt",
        "Infineon\\IntermediateCA\\OptigaEccMfrCA067.crt",
        "Nuvoton\\IntermediateCA\\NPCTxxxECC384LeafCA012110.cer",
        "Nuvoton\\IntermediateCA\\NPCTxxxECC384LeafCA012111.cer",
        "Nuvoton\\IntermediateCA\\NPCTxxxECC384LeafCA022110.cer",
        "Nuvoton\\IntermediateCA\\NPCTxxxECC384LeafCA022111.cer",
        "QC\\IntermediateCA\\qwes_prod_ek_provisioning_intermediate.crt",
        "STMicro\\IntermediateCA\\STSAFE TPM ECC384 Intermediate CA 10.crt",
        "STMicro\\IntermediateCA\\STSAFE TPM ECC384 Intermediate CA 11.crt",
        "NationZ\\IntermediateCA\\NSEccEkCA001.crt",
        "NationZ\\IntermediateCA\\NSEccEkCA002.crt",
        "NationZ\\IntermediateCA\\NSEccEkCA003.crt",
        "NationZ\\IntermediateCA\\NSEccEkCA004.crt",
        "NationZ\\IntermediateCA\\NSEccEkCA005.crt",
        "NationZ\\IntermediateCA\\NSTPMEccEkCA001.crt",
        "NationZ\\IntermediateCA\\NSTPMEccEkCA002.crt",
        "NationZ\\IntermediateCA\\NSTPMEccEkCA003.crt",
        "NationZ\\IntermediateCA\\NSTPMEccEkCA004.crt",
        "NationZ\\IntermediateCA\\NSTPMEccEkCA005.crt",
    ];
    purge_exists("tests/examples/TrustedTPM/", &mut known_validation_issues);
    assert_eq!(0, known_validation_issues.len());

    let mut amd_building_issues = vec![
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-AERFamily-6A668AE95CA8508559C3E1D872F2417D.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-CRDFamily-5B401A1127EA54E3685B06D275FE8399.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-GNFamily-403113170A425ABD6B04CE6BF21FD467.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-GNRFamily-842A9A2652E452CC63DBD8FA9C218ED4.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-HPTFamily-F21A726D76AF588151CA619A0596D812.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-MDNFamily-87A9580E58935BBD40616CCF1820BEEF.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-PHX2Family-3887D9A52A04517246E45296FF1E2F8E.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-PHXFamily-3411EF15082F59EC465D7DEC188BB0A1.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-RMBFamily-D30EE6F7557055BA66AD1A1DD1157D2C.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-RPLFamily-5B8502F0A93A5B6E50D659FED374CF19.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-STPFamily-DE88506F89845CC24D912DBA442CADCD.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-STXFamily-7C4760BD7AC95E2F5336A9D6028B1E10.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-STXHFamily-841ED9E18F875F705AFACAD1CEFAFE37.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-KRKFamily-ACEB8D2B409157C74EB2EE08CED9B645.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-ICA-SHPFamily-EB7F6EC0482058DC50691212B414464A.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-KRKFamily-C1C1ED276EC755E277AD88C79AAE8EE7.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-SHPFamily-56994D25E17B5ED968FDD36ABD64804E.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-RNFamily.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-RVFamily.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-ECC-SSPFamily.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-AERFamily-CCB96594EB1D57D7560EFB6022F67275.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-CRDFamily-B7F5D6F2A3165E235FD1FFBE69F2BFA9.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-GNFamily-639A786220D457236F8C816E1555F565.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-GNRFamily-FE5429C191BE55C2613A0F7DC3360E89.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-HPTFamily-0B7F833A00D15BEB46BA18CCE36E0244.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-MDNFamily-D053AFB18A3059D86723CD7D018489D2.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-PHX2Family-D63C16CBD4705E5B5C91095FD728772B.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-PHXFamily-A993351137005452447E60D15764141E.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-RMBFamily-51ADE34A2F8253525E2321AD63F7B197.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-RPLFamily-1E34E7EF9C15FA479A9F398BC865D60.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-STPFamily-E66DF8C15E99581D7EEFA04D9ECE369A.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-STXFamily-AC721D42534F54F84DBA160B17E1C920.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-ICA-STXHFamily-f9afd54db71d51bc482ed80e4a118f62.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-RNFamily.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-RVFamily.crt",
        "AMD\\IntermediateCA\\AMD-fTPM-RSA-SSPFamily.crt",
    ];
    purge_exists("tests/examples/TrustedTPM/AMD", &mut amd_building_issues);
    assert_eq!(0, amd_building_issues.len());

    let mut infineon_validation_issues = vec![
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_01.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_01.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_02.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_03.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_04.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_05.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_06.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_07.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_08.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_10.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_11.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_12.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_13.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_14.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_15.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_16.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_17.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_18.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_19.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_20.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_21.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_22.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_23.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_25.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_26.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_27.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_28.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_29.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_31.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_32.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_33.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_37.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_39.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_53.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_55.crt",
        "Infineon\\IntermediateCA\\IFX_TPM_EK_Intermediate_CA_63.crt",
    ];
    purge_exists(
        "tests/examples/TrustedTPM/Infineon",
        &mut infineon_validation_issues,
    );
    assert_eq!(0, infineon_validation_issues.len());
}

fn purge_exists(folder: &str, expected: &mut Vec<&str>) {
    for entry in WalkDir::new(folder) {
        match entry {
            Ok(entry) => {
                let path = entry.path();
                if entry.file_type().is_dir() {
                    if let Some(p) = path.to_str() {
                        if p != folder {
                            purge_exists(p, expected);
                        } else {
                            continue;
                        }
                    }
                } else {
                    let mut filename = match path.to_str() {
                        Some(filename) => filename.to_string(),
                        None => continue,
                    };
                    filename = filename.replace("tests/examples/TrustedTPM/", "");
                    filename = filename.replace("/", "\\");
                    expected.retain(|&x| !filename.eq(x));
                }
            }
            Err(e) => {
                println!("Failed to traverse directory: {e:?}");
            }
        }
    }
}

#[tokio::test]
async fn test_cab() {
    use tpm_cab_verify::CabVerifyParts;
    let trusted_tpm = include_bytes!("../TrustedTpm.cab");
    let cursor = std::io::Cursor::new(trusted_tpm);
    let cvp = CabVerifyParts::new(cursor).unwrap();
    assert_eq!(
        "193F0F83B5B358A97F893065A98B15C13C5A3056F0DDA1CF3C48812345B80C09",
        buffer_to_hex(&cvp.digest)
    );
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut cps = CertificationPathSettings::default();
    cps.set_time_of_interest(1735562393);
    cvp.verify(&mut pe, &cps).await.unwrap();
}

#[cfg(test)]
/// Some attestations from TPM-based VSCs are signed using RSA with SHA1. Because this algorithm is
/// so antiquated, support for it was not included in the `certval` crate. This implementation of the
/// `verify_signature_message` interface only supports RSA with SHA-1 and is added to the collection
/// usually used in a PkiEnvironment to support these cases.
pub fn verify_signature_message_rust_crypto_sha1(
    _pe: &PkiEnvironment,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> certval::Result<()> {
    if SHA_1_WITH_RSA_ENCRYPTION != signature_alg.oid {
        return Err(certval::Error::Unrecognized);
    }

    let enc_spki = match spki.to_der() {
        Ok(enc_spki) => enc_spki,
        Err(e) => {
            error!("Failed to encode public key passed to verify_signature_message_rust_crypto_sha1: {e:?}");
            return Err(certval::Error::Asn1Error(e));
        }
    };

    let rsa = match RsaPublicKey::from_public_key_der(&enc_spki) {
        Ok(rsa) => rsa,
        Err(e) => {
            error!("Failed to parse public key passed to verify_signature_message_rust_crypto_sha1 as an RSA public key: {e:?}");
            return Err(certval::Error::ParseError);
        }
    };

    let hash_to_verify = Sha1::digest(message_to_verify);
    let ps = Pkcs1v15Sign::new::<Sha1>();
    rsa.verify(ps, hash_to_verify.as_slice(), signature)
        .map_err(|_err| {
            certval::Error::PathValidation(PathValidationStatus::SignatureVerificationFailure)
        })
}

// Call this from unit tests when debugging.
#[allow(dead_code)]
#[cfg(test)]
fn init_console_logging() {
    use log::LevelFilter;
    use log4rs::{
        append::console::ConsoleAppender,
        config::{Appender, Config, Root},
        encode::pattern::PatternEncoder,
    };
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{m}{n}")))
        .build();
    match Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))
    {
        Ok(config) => {
            let handle = log4rs::init_config(config);
            if let Err(e) = handle {
                println!(
                    "ERROR: failed to configure logging for stdout with {:?}. Continuing without logging.",
                    e
                );
            }
        }
        Err(e) => {
            println!("ERROR: failed to prepare default logging configuration with {:?}. Continuing without logging", e);
        }
    }
}
