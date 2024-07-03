/// Process the TrustedTmp.cab file whenever it changes.
#[tokio::main]
async fn main() {
    println!("cargo::rerun-if-changed=TrustedTpm.cab");
    println!("cargo::rerun-if-changed=ta.cbor");
    println!("cargo::rerun-if-changed=ca.cbor");
    println!("cargo::warning=Processing TrustedTpm.cab");
    let timer = Instant::now();
    process_cab(
        "TrustedTpm.cab",
        "ta.cbor",
        "valid_ca.cbor",
        "invalid_ca.cbor",
        "all_ca.cbor",
    )
    .await;
    println!(
        "cargo::warning=Completed TPM CAB processing in {} seconds",
        timer.elapsed().as_secs_f64()
    );
}

use base64ct::{Base64, Encoding};
use std::io::BufRead;
use std::time::Instant;
use std::{ffi::OsStr, fs, io::Read, path::Path};

use cab;

use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{digest::const_oid::db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION, Digest, Sha256};

use x509_cert::{
    der::Encode,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

use certval::{
    CertFile, CertSource, CertVector, CertificationPath, CertificationPathBuilderFormats,
    CertificationPathResults, CertificationPathSettings, PDVCertificate, PathValidationStatus,
    PkiEnvironment, TaSource,
};
use tpm_cab_verify::CabVerifyParts;

pub async fn process_cab(
    file_name: &str,
    ta_cbor: &str,
    valid_ca_cbor: &str,
    invalid_ca_cbor: &str,
    all_ca_cbor: &str,
) {
    // mut is used when unverified_amd_roots is not used
    #[allow(unused_mut)]
    let mut known_building_issues: Vec<&str> = vec![];

    // mut is used when sha1_certs is not used
    #[allow(unused_mut)]
    let mut known_validation_issues = vec![
        "Infineon\\IntermediateCA\\Infineon_OPTIGA(TM)_TPM_2.0_ECC_CA_054.crt",
        "Infineon\\IntermediateCA\\Infineon_OPTIGA(TM)_TPM_2.0_ECC_CA_056.crt",
        "Infineon\\IntermediateCA\\OptigaEccMfrCA052.crt",
        "Infineon\\IntermediateCA\\OptigaEccMfrCA053.crt",
        "Infineon\\IntermediateCA\\OptigaEccMfrCA061.crt",
        "Infineon\\IntermediateCA\\OptigaEccMfrCA064.crt",
        "Nuvoton\\IntermediateCA\\NPCTxxxECC384LeafCA012110.cer",
        "Nuvoton\\IntermediateCA\\NPCTxxxECC384LeafCA012111.cer",
        "Nuvoton\\IntermediateCA\\NPCTxxxECC384LeafCA022110.cer",
        "Nuvoton\\IntermediateCA\\NPCTxxxECC384LeafCA022111.cer",
        "QC\\IntermediateCA\\qwes_prod_ek_provisioning_intermediate.crt",
        "STMicro\\IntermediateCA\\STSAFE TPM ECC384 Intermediate CA 10.crt",
        "STMicro\\IntermediateCA\\STSAFE TPM ECC384 Intermediate CA 11.crt",
    ];

    let ta_cbor_hash = match fs::read(ta_cbor) {
        Ok(ta_cbor) => Sha256::digest(ta_cbor).as_slice().to_vec(),
        Err(e) => {
            println!("cargo::warning=Failed to read previous TA CBOR from {ta_cbor}. Ignoring and continuing. Error: {e:?}");
            vec![]
        }
    };
    let ca_cbor_hash = match fs::read(valid_ca_cbor) {
        Ok(ca_cbor) => Sha256::digest(ca_cbor).as_slice().to_vec(),
        Err(e) => {
            println!("cargo::warning=Failed to read previous CA CBOR from {valid_ca_cbor}. Ignoring and continuing. Error: {e:?}");
            vec![]
        }
    };
    let cab_hash = match fs::read(file_name) {
        Ok(cab_buf) => Sha256::digest(cab_buf).as_slice().to_vec(),
        Err(e) => {
            println!("cargo::warning=Failed to read previous CA CBOR from {file_name}. Ignoring and continuing. Error: {e:?}");
            vec![]
        }
    };

    let source = "https://go.microsoft.com/fwlink/?linkid=2097925";
    let response = match reqwest::get(source).await {
        Ok(response) => response,
        Err(e) => {
            println!(
                "cargo::warning=Failed to download TPM CAB file from {source}. Error: {e:?}"
            );
            return;
        }
    };
    if let Ok(bytes) = response.bytes().await {
        if cab_hash != Sha256::digest(bytes.clone()).to_vec() {
            let cursor = std::io::Cursor::new(bytes.to_vec());
            let cvp = CabVerifyParts::new(cursor).unwrap();
            let mut pe = PkiEnvironment::default();
            pe.populate_5280_pki_environment();
            let cps = CertificationPathSettings::default();
            match cvp.verify(&mut pe, &cps).await {
                Ok(()) => {
                    match fs::write("TrustedTpm.cab", bytes) {
                        Ok(_) => {
                            println!("cargo::warning=A new TPM CAB file was downloaded and verified from {source} and \
                            saved as TrustedTpm.cab for use in this build process");
                        }
                        Err(e) => {
                            println!("cargo::warning=A new TPM CAB file was downloaded and verified from {source}. \
                            An attempted was made to save the file as TrustedTpm.cab failed: {e:?}. \
                            Download and verify it per the instructions at the following URL then put the resulting \
                            file at the root of this crate: https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates");
                        }
                    }
                }
                Err(e) => {
                    println!("cargo::warning=A new TPM CAB file that could not be verified is available \
                    from {source}. Download and verify it per the instructions at the following URL then \
                    put the resulting file at the root of this crate: https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates. \
                    Error: {e:?}");
                }
            }
        } else {
            println!("cargo::warning=No updated TPM CAB file is available from {source}");
        }
    }

    println!("cargo::warning=Reading TPM CAB file from {file_name}...");
    let cab_file = match fs::File::open(file_name) {
        Ok(cab_file) => cab_file,
        Err(e) => {
            println!("cargo::warning=Failed to read TPM CAB file from {file_name} with: {e:?}");
            return;
        }
    };
    let cab_file2 = match fs::File::open(file_name) {
        Ok(cab_file) => cab_file,
        Err(e) => {
            println!("cargo::warning=Failed to read TPM CAB file from {file_name} with: {e:?}");
            return;
        }
    };

    let cvp = match tpm_cab_verify::CabVerifyParts::new(cab_file2) {
        Ok(cvp) => cvp,
        Err(e) => {
            println!("cargo::warning=Failed to parse verification parts from TPM CAB file from {file_name} with: {e:?}");
            return;
        }
    };

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let cps = CertificationPathSettings::default();
    if let Err(e) = cvp.verify(&mut pe, &cps).await {
        println!("cargo::warning=Failed to parse verify TPM CAB file from {file_name} with: {e:?}");
        return;
    } else {
        println!("cargo::warning=Successfully verified TPM CAB file from {file_name}");
    }

    let mut cabinet = match cab::Cabinet::new(cab_file) {
        Ok(cabinet) => cabinet,
        Err(e) => {
            println!("cargo::warning=Failed to parse TPM CAB file from {file_name} with: {e:?}");
            return;
        }
    };

    // Collect file names for TAs and CAs. Reading will be separate owning to need to mutably borrow
    // the cabinet instance for both iteration and reading.
    let mut ta_files: Vec<String> = vec![];
    let mut ca_files: Vec<String> = vec![];
    let mut skipped_files: Vec<String> = vec![];
    let target_file_exts = vec!["der", "crt", "cer"];
    let known_skips = [
        "setup.cmd",
        "setup.ps1",
        "version.txt",
        "AMD\\IntermediateCA\\readme.txt",
    ];

    for folder in cabinet.folder_entries() {
        for file in folder.file_entries() {
            let file_name = file.name();
            let p = Path::new(file_name);
            let ext = p
                .extension()
                .and_then(OsStr::to_str)
                .unwrap_or_default()
                .to_lowercase();
            if file_name.contains("IntermediateCA") && target_file_exts.contains(&ext.as_str()) {
                ca_files.push(file_name.to_string());
            } else if file_name.contains("RootCA") && target_file_exts.contains(&ext.as_str()) {
                ta_files.push(file_name.to_string());
            } else {
                skipped_files.push(file_name.to_string());
            }
        }
    }

    // Read the TAs into a vector then prepare a TAs-only CBOR file to simply use at build time
    let mut ta_store = TaSource::new();
    let mut ta_serialization = CertSource::new();
    for ta in ta_files {
        let mut reader = match cabinet.read_file(&ta) {
            Ok(reader) => reader,
            Err(e) => {
                println!("cargo::warning=Failed to read certificate file from {ta} with: {e:?}. Ignoring and continuing...");
                continue;
            }
        };
        let mut buf = vec![];
        match reader.read_to_end(&mut buf) {
            Ok(_) => {
                println!("Reading {ta}");
                let cf = if buf[0] != 0x30 {
                    match pem_rfc7468::decode_vec(&buf) {
                        Ok(b) => CertFile {
                            filename: ta,
                            bytes: b.1,
                        },
                        Err(e) => {
                            println!(
                                "cargo::warning=Failed to parse certificate from {}: {}",
                                ta, e
                            );
                            continue;
                        }
                    }
                } else {
                    CertFile {
                        filename: ta,
                        bytes: buf,
                    }
                };

                ta_store.push(cf.clone());
                ta_serialization.push(cf);
            }
            Err(e) => {
                println!("cargo::warning=failed to read TA certificate from {ta}. Ignoring and continuing. Error: {e:?}");
            }
        }
    }

    #[cfg(feature = "unverified_amd_roots")]
    {
        let amd_eng_root1 =
            include_bytes!("tests/examples/23452201D41C5AB064032BD23F158FEF.crt").to_vec();
        let amd_eng_root2 =
            include_bytes!("tests/examples/264D39A23CEB5D5B49D610044EEBD121.crt").to_vec();

        let cf1 = CertFile {
            filename: "examples/23452201D41C5AB064032BD23F158FEF.crt".to_string(),
            bytes: amd_eng_root1,
        };
        let cf2 = CertFile {
            filename: "examples/264D39A23CEB5D5B49D610044EEBD121.crt".to_string(),
            bytes: amd_eng_root2,
        };
        ta_store.push(cf1);
        ta_store.push(cf2);
    }
    #[cfg(not(feature = "unverified_amd_roots"))]
    {
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
        known_building_issues.append(&mut amd_building_issues);
    }

    if let Err(e) = ta_store.initialize() {
        println!(
            "cargo::warning=failed to initialize TA store. Ignoring and continuing. Error: {e:?}"
        );
    }

    match ta_serialization.serialize(CertificationPathBuilderFormats::Cbor) {
        Ok(graph) => {
            if ta_cbor_hash != Sha256::digest(&graph).as_slice().to_vec() {
                fs::write(ta_cbor, graph.as_slice())
                    .expect("Unable to write generated CBOR file with trust anchor certificates");
            }
        }
        Err(e) => {
            println!("cargo::warning=failed to write TA collection to a CBOR file. Ignoring and continuing. Error: {e:?}");
        }
    }

    let mut cert_source = CertSource::new();
    for ca in ca_files {
        let mut reader = match cabinet.read_file(&ca) {
            Ok(reader) => reader,
            Err(e) => {
                println!("cargo::warning=Failed to read certificate file from {ca} with: {e:?}. Ignoring and continuing...");
                continue;
            }
        };
        let mut buf = vec![];
        match reader.read_to_end(&mut buf) {
            Ok(_) => {
                println!("Reading {ca}");
                let cf = if buf[0] != 0x30 {
                    match pem_rfc7468::decode_vec(&buf) {
                        Ok(b) => CertFile {
                            filename: ca,
                            bytes: b.1,
                        },
                        Err(e) => {
                            if let Ok(b) = decode_broken_pem(&buf) {
                                CertFile {
                                    filename: ca,
                                    bytes: b,
                                }
                            } else {
                                println!(
                                    "cargo::warning=Failed to parse certificate from {}: {}",
                                    ca, e
                                );
                                continue;
                            }
                        }
                    }
                } else {
                    CertFile {
                        filename: ca,
                        bytes: buf,
                    }
                };

                cert_source.push(cf);
            }
            Err(e) => {
                println!("cargo::warning=failed to read CA certificate from {ca}. Ignoring and continuing. Error: {e:?}");
            }
        }
    }

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_store));

    #[cfg(feature = "sha1_certs")]
    {
        pe.add_verify_signature_message_callback(verify_signature_message_rust_crypto_sha1)
    }
    #[cfg(not(feature = "sha1_certs"))]
    {
        let mut infineon_validation_issues = vec![
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
        known_validation_issues.append(&mut infineon_validation_issues);
    }

    let mut cps = CertificationPathSettings::default();
    cps.set_retrieve_from_aia_sia_http(false);
    cps.set_check_revocation_status(false);

    if let Err(e) = cert_source.initialize(&cps) {
        println!("cargo::warning=failed to initialize certificate store. Ignoring and continuing. Error: {e:?}");
    }

    cert_source.find_all_partial_paths(&pe, &cps);
    match cert_source.serialize(CertificationPathBuilderFormats::Cbor) {
        Ok(graph) => {
            if ca_cbor_hash != Sha256::digest(&graph).as_slice().to_vec() {
                fs::write(all_ca_cbor, graph.as_slice())
                    .expect("Unable to write generated CBOR file with CAs and partial paths");
            }
        }
        Err(e) => {
            println!("cargo::warning=failed to write CAs and partial paths to a CBOR file. Ignoring and continuing. Error: {e:?}");
        }
    }

    let ca_certs = cert_source.get_buffers();
    pe.add_certificate_source(Box::new(cert_source));

    let mut cert_source_valid = CertSource::new();
    let mut cert_source_invalid = CertSource::new();

    // verify each CA cert, saving those that verify and discarding those that do not
    for cf in ca_certs {
        let mut valid = false;
        let mut errors = vec![];
        let mut paths: Vec<CertificationPath> = vec![];
        if let Ok(cert) = PDVCertificate::try_from(cf.bytes.as_slice()) {
            if pe
                .get_paths_for_target(&cert, &mut paths, 0, cps.get_time_of_interest())
                .is_ok()
            {
                if paths.is_empty() {
                    if !known_building_issues.contains(&cf.filename.as_str()) {
                        println!("cargo::warning=failed to find any certification paths for certificate from {}. Ignoring and continuing.", cf.filename);
                    }
                    cert_source_invalid.push(cf);
                    continue;
                } else {
                    for path in paths.iter_mut() {
                        let mut cpr = CertificationPathResults::new();
                        match pe.validate_path(&pe, &cps, path, &mut cpr) {
                            Ok(_) => {
                                valid = true;
                                break;
                            }
                            Err(e) => {
                                errors.push(e);
                            }
                        }
                    }
                    if !valid && !known_validation_issues.contains(&cf.filename.as_str()) {
                        println!("cargo::warning=failed to validate certificate from {}. Ignoring and continuing. Error: {:?}", cf.filename, errors);
                        cert_source_invalid.push(cf);
                    } else {
                        cert_source_valid.push(cf);
                    }
                }
            }
        };
    }

    if let Err(e) = cert_source_valid.initialize(&cps) {
        println!("cargo::warning=failed to initialize certificate store. Ignoring and continuing. Error: {e:?}");
    }

    cert_source_valid.find_all_partial_paths(&pe, &cps);

    // serialize only the CA certs for which a valid path was found
    match cert_source_valid.serialize(CertificationPathBuilderFormats::Cbor) {
        Ok(graph) => {
            if ca_cbor_hash != Sha256::digest(&graph).as_slice().to_vec() {
                fs::write(valid_ca_cbor, graph.as_slice())
                    .expect("Unable to write generated CBOR file with CAs and partial paths");
            }
        }
        Err(e) => {
            println!("cargo::warning=failed to write CAs and partial paths to a CBOR file. Ignoring and continuing. Error: {e:?}");
        }
    }

    match cert_source_invalid.serialize(CertificationPathBuilderFormats::Cbor) {
        Ok(graph) => {
            if ca_cbor_hash != Sha256::digest(&graph).as_slice().to_vec() {
                fs::write(invalid_ca_cbor, graph.as_slice())
                    .expect("Unable to write generated CBOR file with CAs and partial paths");
            }
        }
        Err(e) => {
            println!("cargo::warning=failed to write CAs and partial paths to a CBOR file. Ignoring and continuing. Error: {e:?}");
        }
    }

    for skipped in skipped_files {
        if !known_skips.contains(&skipped.as_str()) {
            println!("cargo::warning={skipped} appears to be neither a TA nor a CA");
        }
    }
}

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

/// Some intermediate CA certificates are signed using RSA with SHA1. Because this algorithm is
/// so antiquated, support for it was not included in the `certval` crate. This implementation of the
/// `verify_signature_message` interface only supports RSA with SHA-1 and is added to the collection
/// usually used in a PkiEnvironment to support these cases. While it exists in attestation_verifier,
/// including that here would create a cyclic dependency, hence the duplication.
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
            println!("cargo::warning=Failed to encode public key passed to verify_signature_message_rust_crypto_sha1: {e:?}");
            return Err(certval::Error::Asn1Error(e));
        }
    };

    let rsa = match RsaPublicKey::from_public_key_der(&enc_spki) {
        Ok(rsa) => rsa,
        Err(e) => {
            println!("cargo::warning=Failed to parse public key passed to verify_signature_message_rust_crypto_sha1 as an RSA public key: {e:?}");
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
