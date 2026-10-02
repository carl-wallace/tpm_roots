#![doc = include_str!("../README.md")]

use log::error;
use std::sync::LazyLock;

use certval::{
    CertFile, CertSource, CertVector, CertificationPathSettings, PkiEnvironment, Result, TaSource,
};
use certval_stores_core::serialize_environment;
use x509_cert::{anchor::TrustAnchorInfo, der::Decode, Certificate};

// The material comes from `certval_stores_tpm`, which owns the cabinet, the refresh and the
// conformance tests. What is left here is the shape the original crate presented, kept so
// `attestation_verifier` compiles against it unchanged; retire it once that migrates.
//
// The two statics remain the crate's centre of gravity: every other function reads one of them, so
// re-sourcing the pair moves the whole crate onto the provider.

/// CBOR-formatted data structure containing trust anchors for the TPM vendor roots.
///
/// Serialized from the provider's anchors on first use rather than embedded, because a provider
/// carries DER roots and no CBOR. `serialize_environment` writes the anchors as a `CertSource`
/// holding no partial paths, which is the form [`certval::TaSource::new_from_cbor`] reads. Leaked
/// deliberately: the buffer lives as long as the process, which is what the `&'static` this type
/// always promised means here. An empty slice, with the reason logged, if the provider cannot be
/// serialized -- the same fail-soft the CBOR parsing below has always had.
///
/// Not byte-identical to the `ta.cbor` this crate used to embed. Anchor labels are serialized
/// alongside the certificates and a provider has no filenames to reproduce, so the bytes differ
/// while the anchors do not.
pub static TA_CBOR: LazyLock<&'static [u8]> = LazyLock::new(|| {
    match serialize_environment(&[certval_stores_tpm::provider()], certval_stores_tpm::TPM) {
        Ok(store) => Box::leak(store.ta_cbor.into_boxed_slice()),
        Err(e) => {
            error!("Failed to serialize TPM trust anchors from certval_stores_tpm: {e:?}");
            &[]
        }
    }
});

/// CBOR-formatted data structure containing intermediate CA certificates for the TPM vendor roots
/// along with partial path information (relative to the trust anchors in `TA_CBOR`)
///
/// Taken straight from the provider, which embeds this store already built; no serialization and
/// no allocation.
pub static CA_CBOR: LazyLock<&'static [u8]> =
    LazyLock::new(|| {
        match certval_stores_tpm::provider()
            .entries()
            .into_iter()
            .find(|e| e.id == certval_stores_tpm::TPM)
            .and_then(|e| e.cert_store_cbor)
        {
            Some(cbor) => cbor,
            None => {
                error!("certval_stores_tpm served no CA store for the tpm environment");
                &[]
            }
        }
    });

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------

/// Retrieve intermediate CA certificates as `CertFile` objects
fn get_cas_as_cert_files() -> Result<Vec<CertFile>> {
    let mut cas = vec![];
    let cert_store = match CertSource::new_from_cbor(&CA_CBOR) {
        Ok(cert_store) => cert_store,
        Err(e) => {
            error!("Failed to parse ca.cbor file as a CertSource: {e:?}");
            return Err(e);
        }
    };

    let certs = cert_store.get_buffers();
    for cert in certs {
        cas.push(cert);
    }

    Ok(cas)
}

/// Updates a `PkiEnvironment` object to include a `TaSource` containing TPM roots and `CertSource`
/// containing intermediate CA certificates.
///
/// The `CertificationPathSettings` is used to initialize the `CertSource`, primarily to provide a
/// time of interest value.
///
/// Root certificates and intermediate CA certificates come from `certval_stores_tpm`, which builds
/// them from Microsoft's `TrustedTpm.cab` and commits the cabinet it used.
fn prepare_certval_environment_internal(
    pe: &mut PkiEnvironment,
    cps: &CertificationPathSettings,
) -> Result<()> {
    let mut ta_store = match TaSource::new_from_cbor(&TA_CBOR) {
        Ok(ta_store) => ta_store,
        Err(e) => {
            error!("Failed to parse ta.cbor file as a TaSource: {e:?}");
            return Err(e);
        }
    };
    if let Err(e) = ta_store.initialize() {
        error!("Failed to initialize TaSource: {e:?}");
        return Err(e);
    }

    let mut cert_store = match CertSource::new_from_cbor(&CA_CBOR) {
        Ok(cert_store) => cert_store,
        Err(e) => {
            error!("Failed to parse ca.cbor file as a CertSource: {e:?}");
            return Err(e);
        }
    };

    if let Err(e) = cert_store.initialize(cps) {
        error!("Failed to initialize CertSource: {e:?}");
        return Err(e);
    }
    cert_store.find_all_partial_paths(pe, cps);

    pe.add_trust_anchor_source(Box::new(ta_store));
    pe.add_certificate_source(Box::new(cert_store));

    Ok(())
}

/// Updates a `PkiEnvironment` object to include a `TaSource` containing TPM roots and intermediate
/// CA certificates.
///
/// This alternative is provided owing to the broken nature of the TPM PKI. Revocation checking
/// ability is extremely spotty, so not much is gained by treating the intermediate CA certificates
/// as intermediates.
///
/// The `CertificationPathSettings` is used to initialize the `CertSource`, primarily to provide a
/// time of interest value.
///
/// Root certificates and intermediate CA certificates come from `certval_stores_tpm`, which builds
/// them from Microsoft's `TrustedTpm.cab` and commits the cabinet it used.
fn prepare_certval_environment_cas_as_tas(
    pe: &mut PkiEnvironment,
    cps: &CertificationPathSettings,
) -> Result<()> {
    let mut ta_store = match TaSource::new_from_cbor(&TA_CBOR) {
        Ok(ta_store) => ta_store,
        Err(e) => {
            error!("Failed to parse ta.cbor file as a TaSource: {e:?}");
            return Err(e);
        }
    };

    let ca_bufs = match get_cas_as_cert_files() {
        Ok(ca_bufs) => ca_bufs,
        Err(e) => {
            error!("Failed to get CA certificate buffers");
            return Err(e);
        }
    };

    for ca_buf in ca_bufs {
        ta_store.push(ca_buf);
    }
    if let Err(e) = ta_store.initialize() {
        error!("Failed to initialize TaSource: {e:?}");
        return Err(e);
    }

    let mut cert_source = CertSource::default();
    if let Err(e) = cert_source.initialize(cps) {
        error!("Failed to initialize CertSource: {e:?}");
        return Err(e);
    }

    pe.add_trust_anchor_source(Box::new(ta_store));
    pe.add_certificate_source(Box::new(cert_source));
    Ok(())
}

//------------------------------------------------------------------------------------
// Public methods
//------------------------------------------------------------------------------------

/// Updates a `PkiEnvironment` object to include TPM roots and intermediate CA certificates needed
/// to validate AIK certificates from TPM-backed virtual smart cards.
///
/// The `CertificationPathSettings` is used to initialize the `CertSource`, primarily to provide a
/// time of interest value.
///
/// The `treat_cas_as_tas` variable will determine how intermediate CAs are handled. When false, the
/// PkiEnvironment receives a `TaSource` containing trust anchors and a `CertSource` containing intermediate
/// CA certificates. When true, the PkiEnvironment receives a `TaSource` containing both trust anchors
/// and intermediate CA certificates, i.e., the intermediate CAs are treated as trust anchors.
///
/// Root certificates and intermediate CA certificates come from `certval_stores_tpm`, which builds
/// them from Microsoft's `TrustedTpm.cab` and commits the cabinet it used.
pub fn prepare_certval_environment(
    pe: &mut PkiEnvironment,
    cps: &CertificationPathSettings,
    treat_cas_as_tas: bool,
) -> Result<()> {
    if treat_cas_as_tas {
        prepare_certval_environment_cas_as_tas(pe, cps)
    } else {
        prepare_certval_environment_internal(pe, cps)
    }
}

/// Returns a vector of `TrustAnchorInfo` objects corresponding to the root certificates carried by
/// `certval_stores_tpm`.
pub fn get_tas() -> Result<Vec<TrustAnchorInfo>> {
    let mut tas = vec![];
    let ta_store = match TaSource::new_from_cbor(&TA_CBOR) {
        Ok(ta_store) => ta_store,
        Err(e) => {
            error!("Failed to parse ta.cbor file as a TaSource: {e:?}");
            return Err(e);
        }
    };

    let certs = ta_store.get_tas();
    for cert in certs {
        match TrustAnchorInfo::from_der(&cert.bytes) {
            Ok(tai) => tas.push(tai),
            Err(e) => {
                error!("Failed to parse certificate from {} as a TrustAnchorInfo. Ignoring and continuing. Error: {e:?}", cert.filename);
            }
        }
    }

    Ok(tas)
}

/// Returns a vector of `Certificate` objects corresponding to the intermediate CA certificates
/// carried by `certval_stores_tpm`.
pub fn get_cas() -> Result<Vec<Certificate>> {
    let mut cas = vec![];
    let cert_store = match CertSource::new_from_cbor(&CA_CBOR) {
        Ok(cert_store) => cert_store,
        Err(e) => {
            error!("Failed to parse ca.cbor file as a CertSource: {e:?}");
            return Err(e);
        }
    };

    let certs = cert_store.get_buffers();
    for cert in certs {
        match Certificate::from_der(&cert.bytes) {
            Ok(cert) => cas.push(cert),
            Err(e) => {
                error!("Failed to parse certificate from {} as a Certificate. Ignoring and continuing. Error: {e:?}", cert.filename);
            }
        }
    }

    Ok(cas)
}
