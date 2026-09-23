//! The facade still presents what it presented when the material lived here.
//!
//! `certval_stores_tpm` owns the cabinet, the refresh and the conformance checks, and tests the
//! material itself. What is left to test here is the seam: that each public entry point still
//! yields the same shape over a provider it did over the embedded CBOR. Counts are pinned against
//! the provider rather than restated, so a refresh there moves this suite with it instead of
//! failing it.

use certval::{CertSource, CertVector, CertificationPathSettings, PkiEnvironment, TaSource};

/// Anchors and intermediates the provider carries, read from it rather than hard-coded: this
/// crate's job is to pass them through unchanged, not to have an opinion about how many there are.
fn expected() -> (usize, usize) {
    let entry = certval_stores_tpm::provider()
        .entries()
        .into_iter()
        .find(|e| e.id == certval_stores_tpm::TPM)
        .expect("the tpm environment must be served");
    let cas = CertSource::new_from_cbor(entry.cert_store_cbor.expect("the store carries CAs"))
        .expect("the CA store must load");
    (entry.roots.len(), cas.len())
}

/// `TA_CBOR` is serialized on first use, so this is also what proves the serialization round-trips
/// back through the reader the rest of the crate uses.
#[test]
fn ta_cbor_loads_every_anchor() {
    let (roots, _) = expected();
    let ta_source = TaSource::new_from_cbor(&tpm_roots::TA_CBOR).expect("TA_CBOR must load");
    assert_eq!(ta_source.get_tas().len(), roots);
}

#[test]
fn ca_cbor_loads_every_intermediate() {
    let (_, cas) = expected();
    let cert_source = CertSource::new_from_cbor(&tpm_roots::CA_CBOR).expect("CA_CBOR must load");
    assert_eq!(cert_source.len(), cas);
}

/// The call `attestation_verifier` makes, and the only one it makes.
#[test]
fn prepare_certval_environment_with_cas_as_tas() {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let cps = CertificationPathSettings::default();
    tpm_roots::prepare_certval_environment(&mut pe, &cps, true)
        .expect("the cas-as-tas environment must prepare");

    // Anchors and intermediates land in one TaSource, which is the whole point of the flag.
    let (roots, cas) = expected();
    assert_eq!(pe.get_trust_anchors().len(), roots + cas);
}

#[test]
fn prepare_certval_environment_with_intermediates() {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let cps = CertificationPathSettings::default();
    tpm_roots::prepare_certval_environment(&mut pe, &cps, false)
        .expect("the environment must prepare");

    let (roots, _) = expected();
    assert_eq!(pe.get_trust_anchors().len(), roots);
}

#[test]
fn get_cas_returns_every_intermediate() {
    let (_, cas) = expected();
    assert_eq!(
        tpm_roots::get_cas().expect("get_cas must succeed").len(),
        cas
    );
}

/// `get_tas` decodes each anchor as an RFC 5914 `TrustAnchorInfo`, and the anchors are plain
/// certificates -- as they were in the `ta.cbor` this crate used to embed, so this is not a
/// regression from the provider swap. `TrustAnchorInfo` expects a `SubjectPublicKeyInfo` where a
/// `Certificate` has its `tbsCertificate`, so every decode fails and the function logs and skips.
///
/// Pinned as observed rather than as intended: nothing in the working set calls `get_tas`, which is
/// why it has gone unnoticed. Fixing it is a separate change -- folding a behaviour fix into a
/// material swap would leave nobody able to say which one moved the result.
#[test]
fn get_tas_is_empty_because_the_anchors_are_certificates() {
    assert!(tpm_roots::get_tas()
        .expect("get_tas must succeed")
        .is_empty());
}
