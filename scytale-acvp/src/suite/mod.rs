//! The drivers, one module per algorithm family, and the registry
//! that names every vector set they answer.
//!
//! A driver's `answer` takes a vector set as the server or the
//! vendored `internalProjection.json` gives it and returns the
//! response document: `vsId`, `algorithm`, `mode`, `revision` and
//! `testGroups`, each group its `tgId` and `tests`, each test its
//! `tcId` and the fields the suite's specification names. A group a
//! driver cannot answer is left out, with a note on stderr; the
//! server then fails its cases, and the offline check counts what
//! was answered against the suite's minimum.

use crate::support::{Error, FixedEntropy, list, load, object};
use scytale::Random;
use scytale::random::CtrDrbg;
use serde_json::{Map, Value, json};

/// Answers one vector set.
pub type Answer = fn(&Value, &mut dyn Random) -> Result<Value, Error>;

/// Checks one answered test against the vendored one, for a suite
/// whose stored answers came from NIST's own randomness and cannot
/// be matched field for field: given the vendored group and test,
/// then the answered group and test.
pub type Verify = fn(&Value, &Value, &Value, &Value) -> Result<(), Error>;

/// One vector set the drivers answer.
pub struct Suite {
    /// The vendored directory under `vectors/`.
    pub directory: &'static str,
    pub algorithm: &'static str,
    pub mode: Option<&'static str>,
    pub revision: &'static str,
    pub answer: Answer,
    /// `None` compares every answered field with the vendored one.
    pub verify: Option<Verify>,
    /// The cases the vendored file must yield, so a truncated file or
    /// a driver that skips too much cannot pass vacuously.
    pub minimum: usize,
}

/// Dispatches on an AES key's width: binds `$C` to the AES type of
/// `$key` for `$body`, or returns an error for another width.
macro_rules! aes_width {
    ($key:expr, $C:ident => $body:expr) => {
        match $key.len() {
            16 => {
                type $C = scytale::cipher::aes::Aes128;
                $body
            }
            24 => {
                type $C = scytale::cipher::aes::Aes192;
                $body
            }
            32 => {
                type $C = scytale::cipher::aes::Aes256;
                $body
            }
            n => return Err(Error::new(format!("key of {n} bytes"))),
        }
    };
}

pub mod aes_cbc;
pub mod aes_ccm;
pub mod aes_cfb1;
pub mod aes_cfb128;
pub mod aes_cfb8;
pub mod aes_ctr;
pub mod aes_ecb;
pub mod aes_ff1;
pub mod aes_ff3_1;
pub mod aes_gcm;
pub mod aes_gcm_siv;
pub mod aes_gmac;
pub mod aes_kw;
pub mod aes_kwp;
pub mod aes_ofb;
pub mod aes_xpn;
pub mod aes_xts;
pub mod cmac_aes;
pub mod cshake;
pub mod ctr_drbg;
pub mod ecdsa;
pub mod eddsa;
pub mod hash_drbg;
pub mod hmac;
pub mod kda_hkdf;
pub mod kda_one_step;
pub mod kdf108;
pub mod kmac;
pub mod kts_ifc;
pub mod ml_dsa;
pub mod ml_kem;
pub mod pbkdf;
pub mod rsa_keygen;
pub mod rsa_primitive;
pub mod rsa_sig;
pub mod sha;
pub mod shake;
pub mod slh_dsa;
pub mod tls12_kdf;
pub mod tuple_hash;
pub mod xecdh;

/// The response document for `doc` with `groups` answered.
pub fn response(doc: &Value, groups: Vec<Value>) -> Value {
    let mut out = Map::new();
    for name in ["vsId", "algorithm", "mode", "revision"] {
        if let Some(v) = doc.get(name) {
            out.insert(name.into(), v.clone());
        }
    }
    out.insert("testGroups".into(), Value::Array(groups));
    Value::Object(out)
}

/// Answers every group of `doc` with `f`, which returns the group's
/// answer (its `tests`, and any group-level fields) or `None` to leave
/// the group out. The helper adds `tgId` and names the group in any
/// error.
pub fn answer_groups(
    doc: &Value,
    mut f: impl FnMut(&Value) -> Result<Option<Value>, Error>,
) -> Result<Value, Error> {
    let mut groups = Vec::new();
    for group in list(doc, "testGroups")? {
        let id = group["tgId"].clone();
        let answered =
            f(group).map_err(|e| Error::new(format!("tgId {id}: {e}")))?;
        if let Some(mut answered) = answered {
            answered
                .as_object_mut()
                .ok_or_else(|| Error::new("group answer is not an object"))?
                .insert("tgId".into(), id);
            groups.push(answered);
        }
    }
    Ok(response(doc, groups))
}

/// Answers every test of `group` with `f`, which returns the test's
/// answer fields. The helper adds `tcId`, names the case in any error,
/// and returns the group answer holding the `tests`, to which the
/// driver may add group-level fields.
pub fn answer_tests(
    group: &Value,
    mut f: impl FnMut(&Value) -> Result<Value, Error>,
) -> Result<Option<Value>, Error> {
    let mut tests = Vec::new();
    for t in list(group, "tests")? {
        let id = t["tcId"].clone();
        let mut answered =
            f(t).map_err(|e| Error::new(format!("tcId {id}: {e}")))?;
        answered
            .as_object_mut()
            .ok_or_else(|| Error::new("test answer is not an object"))?
            .insert("tcId".into(), id);
        tests.push(answered);
    }
    Ok(Some(json!({ "tests": tests })))
}

/// Leaves `group` unanswered, saying why on stderr.
pub fn skip(group: &Value, why: &str) -> Result<Option<Value>, Error> {
    eprintln!("tgId {}: skipped, {why}", group["tgId"]);
    Ok(None)
}

/// Every vector set the drivers answer.
pub static SUITES: &[Suite] = &[
    aes("ACVP-AES-CBC-1.0", "ACVP-AES-CBC", aes_cbc::answer, 2156),
    aes("ACVP-AES-CCM-1.0", "ACVP-AES-CCM", aes_ccm::answer, 8310),
    aes("ACVP-AES-CFB1-1.0", "ACVP-AES-CFB1", aes_cfb1::answer, 2144),
    aes(
        "ACVP-AES-CFB128-1.0",
        "ACVP-AES-CFB128",
        aes_cfb128::answer,
        2144,
    ),
    aes("ACVP-AES-CFB8-1.0", "ACVP-AES-CFB8", aes_cfb8::answer, 2144),
    aes("ACVP-AES-CTR-1.0", "ACVP-AES-CTR", aes_ctr::answer, 150),
    aes("ACVP-AES-ECB-1.0", "ACVP-AES-ECB", aes_ecb::answer, 2144),
    aes("ACVP-AES-FF1-1.0", "ACVP-AES-FF1", aes_ff1::answer, 750),
    aes(
        "ACVP-AES-FF3-1-1.0",
        "ACVP-AES-FF3-1",
        aes_ff3_1::answer,
        450,
    ),
    aes("ACVP-AES-GCM-1.0", "ACVP-AES-GCM", aes_gcm::answer, 60),
    aes(
        "ACVP-AES-GCM-SIV-1.0",
        "ACVP-AES-GCM-SIV",
        aes_gcm_siv::answer,
        120,
    ),
    aes("ACVP-AES-GMAC-1.0", "ACVP-AES-GMAC", aes_gmac::answer, 60),
    aes("ACVP-AES-KW-1.0", "ACVP-AES-KW", aes_kw::answer, 7200),
    aes("ACVP-AES-KWP-1.0", "ACVP-AES-KWP", aes_kwp::answer, 7200),
    aes("ACVP-AES-OFB-1.0", "ACVP-AES-OFB", aes_ofb::answer, 2144),
    aes("ACVP-AES-XPN-1.0", "ACVP-AES-XPN", aes_xpn::answer, 120),
    aes("ACVP-AES-XTS-1.0", "ACVP-AES-XTS", aes_xts::answer, 400),
    rev(
        "ACVP-AES-XTS-2.0",
        "ACVP-AES-XTS",
        None,
        "2.0",
        aes_xts::answer,
        800,
    ),
    plain("ACVP-HMAC-SHA2-224-1.0", "HMAC-SHA2-224", hmac::answer, 975),
    plain("ACVP-HMAC-SHA2-256-1.0", "HMAC-SHA2-256", hmac::answer, 975),
    plain("ACVP-HMAC-SHA2-384-1.0", "HMAC-SHA2-384", hmac::answer, 975),
    plain("ACVP-HMAC-SHA2-512-1.0", "HMAC-SHA2-512", hmac::answer, 975),
    plain(
        "ACVP-HMAC-SHA2-512-224-1.0",
        "HMAC-SHA2-512/224",
        hmac::answer,
        975,
    ),
    plain(
        "ACVP-HMAC-SHA2-512-256-1.0",
        "HMAC-SHA2-512/256",
        hmac::answer,
        975,
    ),
    plain("ACVP-HMAC-SHA3-224-1.0", "HMAC-SHA3-224", hmac::answer, 975),
    plain("ACVP-HMAC-SHA3-256-1.0", "HMAC-SHA3-256", hmac::answer, 975),
    plain("ACVP-HMAC-SHA3-384-1.0", "HMAC-SHA3-384", hmac::answer, 975),
    plain("ACVP-HMAC-SHA3-512-1.0", "HMAC-SHA3-512", hmac::answer, 975),
    plain("HMAC-SHA-1-1.0", "HMAC-SHA-1", hmac::answer, 975),
    plain("ACVP-PBKDF-1.0", "PBKDF", pbkdf::answer, 50),
    plain("ACVP-SHA2-224-1.0", "SHA2-224", sha::answer, 517),
    plain("ACVP-SHA2-256-1.0", "SHA2-256", sha::answer, 517),
    plain("ACVP-SHA2-384-1.0", "SHA2-384", sha::answer, 1029),
    plain("ACVP-SHA2-512-1.0", "SHA2-512", sha::answer, 1029),
    plain("ACVP-SHA2-512-224-1.0", "SHA2-512/224", sha::answer, 1029),
    plain("ACVP-SHA2-512-256-1.0", "SHA2-512/256", sha::answer, 1029),
    rev(
        "ACVP-SHA3-224-2.0",
        "SHA3-224",
        None,
        "2.0",
        sha::answer,
        1263,
    ),
    rev(
        "ACVP-SHA3-256-2.0",
        "SHA3-256",
        None,
        "2.0",
        sha::answer,
        1199,
    ),
    rev(
        "ACVP-SHA3-384-2.0",
        "SHA3-384",
        None,
        "2.0",
        sha::answer,
        943,
    ),
    rev(
        "ACVP-SHA3-512-2.0",
        "SHA3-512",
        None,
        "2.0",
        sha::answer,
        687,
    ),
    plain("ACVP-SHAKE-128-1.0", "SHAKE-128", shake::answer, 1905),
    plain("ACVP-SHAKE-256-1.0", "SHAKE-256", shake::answer, 1661),
    plain("CMAC-AES-1.0", "CMAC-AES", cmac_aes::answer, 756),
    checked(
        "DetECDSA-SigGen-FIPS186-5",
        "DetECDSA",
        Some("sigGen"),
        "FIPS186-5",
        ecdsa::answer,
        ecdsa::verify_sig_gen,
        330,
    ),
    rev(
        "ECDSA-KeyGen-FIPS186-5",
        "ECDSA",
        Some("keyGen"),
        "FIPS186-5",
        ecdsa::answer,
        18,
    ),
    rev(
        "ECDSA-KeyVer-FIPS186-5",
        "ECDSA",
        Some("keyVer"),
        "FIPS186-5",
        ecdsa::answer,
        9,
    ),
    checked(
        "ECDSA-SigGen-FIPS186-5",
        "ECDSA",
        Some("sigGen"),
        "FIPS186-5",
        ecdsa::answer,
        ecdsa::verify_sig_gen,
        300,
    ),
    rev(
        "ECDSA-SigVer-FIPS186-5",
        "ECDSA",
        Some("sigVer"),
        "FIPS186-5",
        ecdsa::answer,
        105,
    ),
    rev(
        "EDDSA-KeyGen-1.0",
        "EDDSA",
        Some("keyGen"),
        "1.0",
        eddsa::answer,
        3,
    ),
    rev(
        "EDDSA-KeyVer-1.0",
        "EDDSA",
        Some("keyVer"),
        "1.0",
        eddsa::answer,
        4,
    ),
    rev(
        "EDDSA-SigGen-1.0",
        "EDDSA",
        Some("sigGen"),
        "1.0",
        eddsa::answer,
        84,
    ),
    rev(
        "EDDSA-SigVer-1.0",
        "EDDSA",
        Some("sigVer"),
        "1.0",
        eddsa::answer,
        10,
    ),
    rev(
        "KDA-HKDF-Sp800-56Cr2",
        "KDA",
        Some("HKDF"),
        "Sp800-56Cr2",
        kda_hkdf::answer,
        2000,
    ),
    rev(
        "KDA-OneStep-Sp800-56Cr2",
        "KDA",
        Some("OneStep"),
        "Sp800-56Cr2",
        kda_one_step::answer,
        550,
    ),
    rev(
        "KDA-OneStepNoCounter-Sp800-56Cr2",
        "KDA",
        Some("OneStepNoCounter"),
        "Sp800-56Cr2",
        kda_one_step::answer,
        550,
    ),
    plain("KDF-1.0", "KDF", kdf108::answer, 10950),
    rev(
        "KDF-KMAC-Sp800-108r1",
        "KDF",
        Some("KMAC"),
        "Sp800-108r1",
        kdf108::answer,
        100,
    ),
    plain("KMAC-128-1.0", "KMAC-128", kmac::answer, 800),
    plain("KMAC-256-1.0", "KMAC-256", kmac::answer, 800),
    checked(
        "KTS-IFC-Sp800-56Br2",
        "KTS-IFC",
        None,
        "Sp800-56Br2",
        kts_ifc::answer,
        kts_ifc::verify,
        40,
    ),
    rev(
        "ML-DSA-keyGen-FIPS204",
        "ML-DSA",
        Some("keyGen"),
        "FIPS204",
        ml_dsa::answer,
        75,
    ),
    rev(
        "ML-DSA-sigGen-FIPS204-tr1",
        "ML-DSA",
        Some("sigGen"),
        "FIPS204-tr1",
        ml_dsa::answer,
        180,
    ),
    rev(
        "ML-DSA-sigVer-FIPS204",
        "ML-DSA",
        Some("sigVer"),
        "FIPS204",
        ml_dsa::answer,
        45,
    ),
    rev(
        "ML-KEM-encapDecap-FIPS203-tr1",
        "ML-KEM",
        Some("encapDecap"),
        "FIPS203-tr1",
        ml_kem::answer,
        195,
    ),
    rev(
        "ML-KEM-keyGen-FIPS203",
        "ML-KEM",
        Some("keyGen"),
        "FIPS203",
        ml_kem::answer,
        75,
    ),
    checked(
        "RSA-KeyGen-FIPS186-5",
        "RSA",
        Some("keyGen"),
        "FIPS186-5",
        rsa_keygen::answer,
        rsa_keygen::verify,
        // The sample file has no group the crate's one generation
        // method answers; see the driver.
        0,
    ),
    checked(
        "RSA-SigGen-FIPS186-5",
        "RSA",
        Some("sigGen"),
        "FIPS186-5",
        rsa_sig::answer,
        rsa_sig::verify_sig_gen,
        23,
    ),
    rev(
        "RSA-SigVer-FIPS186-4",
        "RSA",
        Some("sigVer"),
        "FIPS186-4",
        rsa_sig::answer,
        288,
    ),
    rev(
        "RSA-SigVer-FIPS186-5",
        "RSA",
        Some("sigVer"),
        "FIPS186-5",
        rsa_sig::answer,
        126,
    ),
    rev(
        "RSA-SignaturePrimitive-2.0",
        "RSA",
        Some("signaturePrimitive"),
        "2.0",
        rsa_primitive::answer,
        90,
    ),
    rev(
        "RSA-decryptionPrimitive-1.0",
        "RSA",
        Some("decryptionPrimitive"),
        "1.0",
        rsa_primitive::answer,
        1,
    ),
    rev(
        "SLH-DSA-keyGen-FIPS205",
        "SLH-DSA",
        Some("keyGen"),
        "FIPS205",
        slh_dsa::answer,
        120,
    ),
    rev(
        "SLH-DSA-sigGen-FIPS205",
        "SLH-DSA",
        Some("sigGen"),
        "FIPS205",
        slh_dsa::answer,
        168,
    ),
    rev(
        "SLH-DSA-sigVer-FIPS205",
        "SLH-DSA",
        Some("sigVer"),
        "FIPS205",
        slh_dsa::answer,
        168,
    ),
    rev(
        "TLS-v1.2-KDF-RFC7627",
        "TLS-v1.2",
        Some("KDF"),
        "RFC7627",
        tls12_kdf::answer,
        120,
    ),
    plain(
        "TupleHash-128-1.0",
        "TupleHash-128",
        tuple_hash::answer,
        202,
    ),
    plain(
        "TupleHash-256-1.0",
        "TupleHash-256",
        tuple_hash::answer,
        202,
    ),
    rev(
        "XECDH-SSC-RFC7748",
        "XECDH",
        Some("SSC"),
        "RFC7748",
        xecdh::answer,
        25,
    ),
    rev(
        "XECDH-keyGen-RFC7748",
        "XECDH",
        Some("keyGen"),
        "RFC7748",
        xecdh::answer,
        10,
    ),
    plain("cSHAKE-128-1.0", "cSHAKE-128", cshake::answer, 101),
    plain("cSHAKE-256-1.0", "cSHAKE-256", cshake::answer, 101),
    plain("ctrDRBG-1.0", "ctrDRBG", ctr_drbg::answer, 60),
    plain("hashDRBG-1.0", "hashDRBG", hash_drbg::answer, 330),
    rev(
        "hashDRBG-SP800-90Ar1",
        "hashDRBG",
        None,
        "SP800-90Ar1",
        hash_drbg::answer,
        660,
    ),
    plain("hmacDRBG-1.0", "hmacDRBG", hash_drbg::answer, 330),
    rev(
        "hmacDRBG-SP800-90Ar1",
        "hmacDRBG",
        None,
        "SP800-90Ar1",
        hash_drbg::answer,
        660,
    ),
    rev(
        "kdf-components-ansix9.63-1.0",
        "kdf-components",
        Some("ansix9.63"),
        "1.0",
        kda_one_step::answer,
        960,
    ),
];

const fn rev(
    directory: &'static str,
    algorithm: &'static str,
    mode: Option<&'static str>,
    revision: &'static str,
    answer: Answer,
    minimum: usize,
) -> Suite {
    Suite {
        directory,
        algorithm,
        mode,
        revision,
        answer,
        verify: None,
        minimum,
    }
}

const fn checked(
    directory: &'static str,
    algorithm: &'static str,
    mode: Option<&'static str>,
    revision: &'static str,
    answer: Answer,
    verify: Verify,
    minimum: usize,
) -> Suite {
    Suite {
        directory,
        algorithm,
        mode,
        revision,
        answer,
        verify: Some(verify),
        minimum,
    }
}

const fn plain(
    directory: &'static str,
    algorithm: &'static str,
    answer: Answer,
    minimum: usize,
) -> Suite {
    rev(directory, algorithm, None, "1.0", answer, minimum)
}

const fn aes(
    directory: &'static str,
    algorithm: &'static str,
    answer: Answer,
    minimum: usize,
) -> Suite {
    plain(directory, algorithm, answer, minimum)
}

/// Every suite's registration, keyed by its vendored directory: the
/// capability object the server is sent, limited to what the drivers
/// answer. A suite without one is checked offline only: the server
/// has dropped it (XTS 1.0, superseded by 2.0, and FF3-1), though its
/// sample file is still worth answering.
const REGISTRATIONS: &str = include_str!("../../registrations.json");

/// The registration of `suite`, or `None` for a suite the server no
/// longer offers.
pub fn registration(suite: &Suite) -> Result<Option<Value>, Error> {
    let all: Value = serde_json::from_str(REGISTRATIONS)?;
    Ok(all.get(suite.directory).cloned())
}

/// The registrations of `suites`, leaving out the suites the server
/// no longer offers and saying so; see [`registration`].
pub fn registrations(suites: &[&Suite]) -> Result<Vec<Value>, Error> {
    let mut out = Vec::new();
    for suite in suites {
        match registration(suite)? {
            Some(r) => out.push(r),
            None => {
                eprintln!("{}: offline only, not registered", suite.directory)
            }
        }
    }
    Ok(out)
}

/// The suites whose vendored directory, algorithm or mode matches
/// `name`.
pub fn find(name: &str) -> Vec<&'static Suite> {
    SUITES
        .iter()
        .filter(|s| {
            s.directory == name
                || s.algorithm == name
                || s.mode.is_some_and(|m| m == name)
                || format!("{}/{}", s.algorithm, s.mode.unwrap_or("")) == name
        })
        .collect()
}

/// The suites `names` pick out, each name resolved by [`find`], or
/// every suite if there are none. A name nothing matches is an error:
/// a list that meant to cover a suite and missed it must say so,
/// not run less. A suite named twice runs once.
pub fn chosen(names: &[String]) -> Result<Vec<&'static Suite>, Error> {
    if names.is_empty() {
        return Ok(SUITES.iter().collect());
    }
    let mut out = Vec::new();
    for name in names {
        let found = find(name);
        if found.is_empty() {
            return Err(Error::new(format!("no suite named {name}")));
        }
        for s in found {
            if !out.iter().any(|o: &&Suite| std::ptr::eq(*o, s)) {
                out.push(s);
            }
        }
    }
    Ok(out)
}

/// The vendored file of `suite`, or `None` if the vectors are not in
/// this copy.
pub fn vendored(suite: &Suite) -> Option<Value> {
    let doc = load(&format!("{}/internalProjection.json", suite.directory))?;
    assert_eq!(doc["algorithm"], suite.algorithm, "{}", suite.directory);
    if let Some(mode) = suite.mode {
        assert_eq!(doc["mode"], mode, "{}", suite.directory);
    }
    // Not every suite records a revision.
    if !doc["revision"].is_null() {
        assert_eq!(doc["revision"], suite.revision, "{}", suite.directory);
    }
    Some(doc)
}

/// A generator whose output is a function of nothing but the order
/// of the calls, so two runs of one suite answer alike.
pub fn fixed_rng() -> CtrDrbg<FixedEntropy> {
    CtrDrbg::try_new(FixedEntropy::default()).expect("fixed entropy")
}

/// The quick check of `suite`: the vendored file less its slow
/// groups, answered with a fixed generator and compared with the
/// file. The large-data groups hash gigabytes and SLH-DSA signs for
/// a minute, so those wait for [`check_all`], which `cargo
/// test-extended` runs. The Monte Carlo groups stay: a thousand
/// chained calls per case is milliseconds, and they are the only
/// groups that carry state from one call into the next. Returns the
/// cases compared.
///
/// # Panics
///
/// On any difference, naming the group and case, or if nothing was
/// compared in a suite whose minimum says something should be.
pub fn check(suite: &Suite) -> usize {
    let Some(mut doc) = vendored(suite) else {
        return 0;
    };
    trim(suite, &mut doc);
    let count = compared(suite, &doc);
    assert!(
        count > 0 || suite.minimum == 0,
        "{}: nothing compared",
        suite.directory
    );
    count
}

/// Cuts `doc` down to what the quick check answers: the large-data
/// groups go, and SLH-DSA signing keeps one case per group.
fn trim(suite: &Suite, doc: &mut Value) {
    let Some(groups) = doc["testGroups"].as_array_mut() else {
        return;
    };
    groups.retain(|g| g["testType"] != "LDT");
    if suite.algorithm == "SLH-DSA" && suite.mode == Some("sigGen") {
        for group in groups {
            if let Some(tests) = group["tests"].as_array_mut() {
                tests.truncate(1);
            }
        }
    }
}

/// The whole vendored file of `suite` answered and compared, every
/// field against the field of that name, or through `suite.verify`
/// where the file's answers came from NIST's randomness. Returns the
/// cases compared.
///
/// # Panics
///
/// On any difference, naming the group and case, or if fewer cases
/// than the suite's minimum were compared.
pub fn check_all(suite: &Suite) -> usize {
    let Some(doc) = vendored(suite) else {
        return 0;
    };
    let count = compared(suite, &doc);
    assert!(
        count >= suite.minimum,
        "{}: only {count} cases, expected at least {}",
        suite.directory,
        suite.minimum
    );
    count
}

fn compared(suite: &Suite, doc: &Value) -> usize {
    let mut rng = fixed_rng();
    let answered = (suite.answer)(doc, &mut rng)
        .unwrap_or_else(|e| panic!("{}: {e}", suite.directory));
    compare(suite, doc, &answered)
        .unwrap_or_else(|e| panic!("{}: {e}", suite.directory))
}

/// Compares `answered` with `expected`, the vendored file or the
/// server's `/expected`; returns the cases compared.
pub fn compare(
    suite: &Suite,
    expected: &Value,
    answered: &Value,
) -> Result<usize, Error> {
    let mut count = 0;
    for group in list(answered, "testGroups")? {
        let id = &group["tgId"];
        let vendored = list(expected, "testGroups")?
            .iter()
            .find(|g| &g["tgId"] == id)
            .ok_or_else(|| Error::new(format!("tgId {id}: not in the file")))?;
        let tag = |e: Error| Error::new(format!("tgId {id}: {e}"));
        if suite.verify.is_none() {
            compare_fields(group, vendored, &["tests"]).map_err(tag)?;
        }
        for test in list(group, "tests")? {
            let id = &test["tcId"];
            let stored = list(vendored, "tests")?
                .iter()
                .find(|t| &t["tcId"] == id)
                .ok_or_else(|| {
                    Error::new(format!("tcId {id}: not in the file"))
                })
                .map_err(tag)?;
            let tag = |e: Error| tag(Error::new(format!("tcId {id}: {e}")));
            match suite.verify {
                Some(verify) => verify(vendored, stored, group, test),
                None => compare_fields(test, stored, &[]),
            }
            .map_err(tag)?;
            count += 1;
        }
    }
    Ok(count)
}

/// Every field of `answered` but those in `except` must equal the
/// field of that name in `expected`: hex strings regardless of case,
/// arrays element by element, anything else exactly.
fn compare_fields(
    answered: &Value,
    expected: &Value,
    except: &[&str],
) -> Result<(), Error> {
    for (name, value) in object(answered)? {
        if except.contains(&name.as_str()) || name == "tgId" || name == "tcId" {
            continue;
        }
        let stored = expected
            .get(name)
            .ok_or_else(|| Error::new(format!("{name}: not in the file")))?;
        if !same(value, stored) {
            return Err(Error::new(format!(
                "{name}: answered {value}, file has {stored}"
            )));
        }
    }
    Ok(())
}

fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(a), Value::String(b)) => a.eq_ignore_ascii_case(b),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.iter().all(|(k, v)| b.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every suite in full: the Monte Carlo and large-data groups
    /// and all of SLH-DSA. Slow; `cargo test-extended` runs it, and
    /// prints the count the README quotes. `SCYTALE_SUITES` names a
    /// subset, as the `run` command's `--algorithms` does; that is
    /// how CI spreads the run over several jobs.
    ///
    /// The suites run on as many threads as the processor has, as
    /// the harness would run them were they tests of their own, so
    /// that the long ones overlap: the gigabytes of hashing and the
    /// SLH-DSA signatures are an hour serially. A worker takes the
    /// next suite rather than a share, since the lengths vary a
    /// hundredfold, and the files are read one per worker at a time.
    #[test]
    #[ignore]
    fn extended() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let names: Vec<String> = std::env::var("SCYTALE_SUITES")
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let suites = chosen(&names).unwrap_or_else(|e| panic!("{e}"));
        let next = AtomicUsize::new(0);
        let counts: Vec<AtomicUsize> =
            suites.iter().map(|_| AtomicUsize::new(0)).collect();
        let work = || {
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(suite) = suites.get(i) else {
                    break;
                };
                let started = std::time::Instant::now();
                let count = check_all(suite);
                eprintln!(
                    "{}: {count} cases in {:.1} s",
                    suite.directory,
                    started.elapsed().as_secs_f64()
                );
                counts[i].store(count, Ordering::Relaxed);
            }
        };
        // WebAssembly has no threads: spawning one aborts the run.
        let workers = if cfg!(target_family = "wasm") {
            1
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        };
        if workers == 1 {
            work();
        } else {
            std::thread::scope(|scope| {
                for _ in 0..workers {
                    scope.spawn(work);
                }
            });
        }
        let total: usize =
            counts.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        eprintln!(
            "total: {total} cases in {} of {} suites",
            suites.len(),
            SUITES.len()
        );
    }

    #[test]
    fn chosen_by_nothing_is_every_suite() {
        assert_eq!(chosen(&[]).unwrap().len(), SUITES.len());
    }

    #[test]
    fn chosen_by_algorithm_is_each_of_its_suites_once() {
        let names = ["RSA".to_string(), "RSA".to_string()];
        let rsa = chosen(&names).unwrap();
        assert_eq!(
            rsa.len(),
            SUITES.iter().filter(|s| s.algorithm == "RSA").count()
        );
        assert!(rsa.iter().all(|s| s.algorithm == "RSA"));
    }

    #[test]
    fn chosen_by_directory_is_that_suite() {
        let names = ["ACVP-SHA2-256-1.0".to_string()];
        let found = chosen(&names).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].directory, "ACVP-SHA2-256-1.0");
    }

    #[test]
    fn chosen_by_unknown_name_is_an_error() {
        let names = ["SHA2-255".to_string()];
        assert!(chosen(&names).is_err());
    }

    #[test]
    fn registry_names_every_vendored_directory() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("vectors");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        let mut on_disk: Vec<String> = entries
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n != "LICENSE.txt")
            .collect();
        on_disk.sort();
        let mut listed: Vec<String> =
            SUITES.iter().map(|s| s.directory.to_string()).collect();
        listed.sort();
        assert_eq!(on_disk, listed);
    }

    #[test]
    fn trim_drops_large_data_and_keeps_monte_carlo() {
        let file = || {
            json!({"testGroups": [
                {"tgId": 1, "testType": "AFT", "tests": [{"tcId": 1}]},
                {"tgId": 2, "testType": "MCT", "tests": [{"tcId": 2}]},
                {"tgId": 3, "testType": "LDT", "tests": [{"tcId": 3}]},
            ]})
        };
        let suite = plain("x", "x", |_, _| Ok(Value::Null), 0);
        let mut doc = file();
        trim(&suite, &mut doc);
        let kinds: Vec<&str> = doc["testGroups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["testType"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["AFT", "MCT"]);
    }

    #[test]
    fn trim_keeps_one_slh_dsa_signature_per_group() {
        let suite = rev(
            "x",
            "SLH-DSA",
            Some("sigGen"),
            "FIPS205",
            |_, _| Ok(Value::Null),
            0,
        );
        let mut doc = json!({"testGroups": [
            {"tgId": 1, "testType": "AFT",
             "tests": [{"tcId": 1}, {"tcId": 2}, {"tcId": 3}]},
        ]});
        trim(&suite, &mut doc);
        assert_eq!(doc["testGroups"][0]["tests"].as_array().unwrap().len(), 1);
        // Only signing is cut: verification is quick.
        let suite = rev(
            "x",
            "SLH-DSA",
            Some("sigVer"),
            "FIPS205",
            |_, _| Ok(Value::Null),
            0,
        );
        let mut doc = json!({"testGroups": [
            {"tgId": 1, "testType": "AFT", "tests": [{"tcId": 1}, {"tcId": 2}]},
        ]});
        trim(&suite, &mut doc);
        assert_eq!(doc["testGroups"][0]["tests"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn same_ignores_hex_case_and_compares_arrays() {
        assert!(same(&json!("ab"), &json!("AB")));
        assert!(same(&json!([{"a": "ff"}]), &json!([{"a": "FF", "b": 1}])));
        assert!(!same(&json!([1]), &json!([1, 2])));
        assert!(!same(&json!(true), &json!(false)));
    }

    #[test]
    fn compare_names_the_differing_case() {
        let suite = plain("x", "x", |_, _| Ok(Value::Null), 0);
        let file = json!({"testGroups": [{"tgId": 1, "tests": [
            {"tcId": 1, "ct": "AA"}, {"tcId": 2, "ct": "BB"},
        ]}]});
        let good = json!({"testGroups": [{"tgId": 1, "tests": [
            {"tcId": 1, "ct": "aa"}, {"tcId": 2, "ct": "bb"},
        ]}]});
        assert_eq!(compare(&suite, &file, &good).unwrap(), 2);
        let bad = json!({"testGroups": [
            {"tgId": 1, "tests": [{"tcId": 2, "ct": "cc"}]}
        ]});
        let e = compare(&suite, &file, &bad).unwrap_err().message;
        assert_eq!(e, "tgId 1: tcId 2: ct: answered \"cc\", file has \"BB\"");
    }
}
