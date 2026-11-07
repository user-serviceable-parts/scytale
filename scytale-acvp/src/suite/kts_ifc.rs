//! KTS-IFC (SP 800-56Br2): RSA-OAEP key transport, which is what
//! [`pke::rsa`](scytale::pke::rsa) implements, with the key
//! confirmation the scheme asks for.
//!
//! Every group in the suite is `KTS-OAEP-Party_V-confirmation` in
//! the mode `noKdfKc`: the transported secret is the derived keying
//! material itself, with no derivation step in between, and the
//! responder, party V, confirms it with a MAC under the key's
//! leading bits over `"KC_1_V"`, V's identifier, U's, and the
//! ciphertext. The MAC is HMAC-SHA-1 or KMAC-128.
//!
//! A responder group hands over the IUT's private key and the
//! server's ciphertext; the IUT decrypts it and answers the keying
//! material and the tag. An initiator group hands over the server's
//! public key; the IUT chooses the key, encrypts it and answers the
//! ciphertext, the keying material and the tag. The vendored file
//! records the key it chose, which is used where present; OAEP
//! encryption draws a fresh seed, so the ciphertext and the tag over
//! it cannot match the file and are checked by decryption instead.
//!
//! One responder group carries an associated-data pattern, which is
//! the OAEP label: `l` as four big-endian bytes, then the initiator's
//! identifier, then the responder's, then the label from the case.

use super::{answer_groups, answer_tests, skip};
use crate::support::{
    Error, Rng, field, hex, hex_value, int, opt_hex, opt_text, text,
    unknown_test_type,
};
use scytale::Random;
use scytale::hash::Hash;
use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::Sha512;
use scytale::mac::hmac::Hmac;
use scytale::mac::kmac::Kmac128;
use scytale::pke::rsa::{PrivateKey, PublicKey};
use serde_json::{Value, json};

/// The associated-data patterns this driver knows how to build.
const EMPTY: &str = "";
const PARTY_INFO: &str = "l||uPartyInfo||vPartyInfo||label";

/// The modulus every group uses, in bytes.
const MODULUS_LEN: usize = 256;

pub fn answer(doc: &Value, rng: &mut dyn Random) -> Result<Value, Error> {
    answer_groups(doc, |group| {
        if text(group, "testType")? != "AFT" {
            return Err(unknown_test_type(group));
        }
        if let Some(why) = skip_reason(group)? {
            return skip(group, &why);
        }
        let responder = match text(group, "kasRole")? {
            "responder" => true,
            "initiator" => false,
            other => return Err(Error::new(format!("kasRole {other}"))),
        };
        answer_tests(group, |t| {
            if responder {
                respond(group, t)
            } else {
                initiate(group, t, rng)
            }
        })
    })
}

/// Why a group cannot run, or `None` if it can.
fn skip_reason(group: &Value) -> Result<Option<String>, Error> {
    if text(group, "scheme")? != "KTS-OAEP-Party_V-confirmation" {
        return Ok(Some(format!("the scheme {}", group["scheme"])));
    }
    // The registration fixes the mode; the server's groups do not
    // repeat it, and the vendored file does.
    if let Some(mode) = opt_text(group, "kasMode")
        && mode != "noKdfKc"
    {
        return Ok(Some(format!(
            "{mode} derives the key rather than transporting it"
        )));
    }
    if text(group, "keyConfirmationDirection")? != "unilateral" {
        return Ok(Some("bilateral key confirmation".into()));
    }
    let kts = field(group, "ktsConfiguration")?;
    let hash = text(kts, "hashAlg")?;
    if hash != "SHA2-512" && hash != "SHA-1" {
        return Ok(Some(format!("OAEP under {hash}")));
    }
    let mac = text(field(group, "macConfiguration")?, "macType")?;
    if mac != "HMAC-SHA-1" && mac != "KMAC-128" {
        return Ok(Some(format!("key confirmation under {mac}")));
    }
    if int(group, "modulo")? != 2048 {
        return Ok(Some(format!("a {}-bit modulus", group["modulo"])));
    }
    let pattern = text(kts, "associatedDataPattern")?;
    if pattern != EMPTY && pattern != PARTY_INFO {
        return Ok(Some(format!("the pattern {pattern}")));
    }
    // An empty pattern makes the encoding moot; a built one must say
    // how its pieces join.
    if pattern == PARTY_INFO && text(kts, "encoding")? != "concatenation" {
        return Ok(Some(format!("the encoding {}", kts["encoding"])));
    }
    Ok(None)
}

/// The initiator's and the responder's identifiers: the initiator
/// is U, so which comes first depends on which side the IUT is.
fn parties(group: &Value) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let iut = hex(group, "iutId")?;
    let server = hex(group, "serverId")?;
    Ok(match text(group, "kasRole")? {
        "responder" => (server, iut),
        _ => (iut, server),
    })
}

/// The OAEP label a group asks for, for one case.
fn label(group: &Value, t: &Value) -> Result<Vec<u8>, Error> {
    let kts = field(group, "ktsConfiguration")?;
    if text(kts, "associatedDataPattern")? == EMPTY {
        return Ok(Vec::new());
    }
    let l = int(group, "l")? as u32;
    let (u, v) = parties(group)?;
    let mut out = Vec::new();
    out.extend_from_slice(&l.to_be_bytes());
    out.extend_from_slice(&u);
    out.extend_from_slice(&v);
    out.extend_from_slice(&hex(field(t, "ktsParameter")?, "label")?);
    Ok(out)
}

/// Whether OAEP runs over SHA-1 rather than SHA-512.
fn sha1(group: &Value) -> Result<bool, Error> {
    Ok(text(field(group, "ktsConfiguration")?, "hashAlg")? == "SHA-1")
}

/// V's key-confirmation tag over the ciphertext `c`, under the
/// leading bits of the transported key `k`.
fn tag(group: &Value, k: &[u8], c: &[u8]) -> Result<Vec<u8>, Error> {
    let mac = field(group, "macConfiguration")?;
    let key_len = int(mac, "keyLen")? as usize / 8;
    let key = k
        .get(..key_len)
        .ok_or_else(|| Error::new("the key is shorter than the MAC key"))?;
    let (u, v) = parties(group)?;
    let mut data = b"KC_1_V".to_vec();
    data.extend_from_slice(&v);
    data.extend_from_slice(&u);
    data.extend_from_slice(c);
    mac_over(group, key, &data)
}

/// The group's MAC of `data` under `key`, at the group's length.
fn mac_over(group: &Value, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let mac = field(group, "macConfiguration")?;
    let mac_len = int(mac, "macLen")? as usize / 8;
    match text(mac, "macType")? {
        "HMAC-SHA-1" => {
            let full = Hmac::<Sha1>::mac(key, data);
            full.as_ref()
                .get(..mac_len)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| Error::new(format!("macLen {mac_len}")))
        }
        "KMAC-128" => {
            // SP 800-56C names "KC" as KMAC's customization for key
            // confirmation.
            let mut kmac = Kmac128::new(key, b"KC");
            kmac.update(data);
            let mut out = vec![0u8; mac_len];
            kmac.finalize_to(&mut out);
            Ok(out)
        }
        other => Err(Error::new(format!("macType {other}"))),
    }
}

fn decrypt<H: Hash + Default>(
    key: &PrivateKey,
    label: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut out = [0u8; MODULUS_LEN];
    let len = key.decrypt_oaep::<H>(label, ciphertext, &mut out)?;
    Ok(out[..len].to_vec())
}

/// Decrypts `c` under `key` and checks the key is `l` bits.
fn recover(
    group: &Value,
    key: &PrivateKey,
    label: &[u8],
    c: &[u8],
) -> Result<Vec<u8>, Error> {
    let k = if sha1(group)? {
        decrypt::<Sha1>(key, label, c)?
    } else {
        decrypt::<Sha512>(key, label, c)?
    };
    let bits = int(group, "l")?;
    if k.len() as u64 * 8 != bits {
        return Err(Error::new(format!(
            "transported {} bits, expected {bits}",
            k.len() * 8
        )));
    }
    Ok(k)
}

/// The IUT as responder: it holds the private key the case gives in
/// full and decrypts the server's ciphertext.
fn respond(group: &Value, t: &Value) -> Result<Value, Error> {
    let key = PrivateKey::try_new(
        &hex(t, "iutN")?,
        &hex(t, "iutE")?,
        &hex(t, "iutD")?,
    )?;
    if key.bits() != 2048 {
        return Err(Error::new(format!("a {}-bit key", key.bits())));
    }
    let c = hex(t, "serverC")?;
    let k = recover(group, &key, &label(group, t)?, &c)?;
    // With no derivation step the transported key is the keying
    // material.
    Ok(json!({
        "dkm": hex_value(&k),
        "tag": hex_value(&tag(group, &k, &c)?),
    }))
}

/// The IUT as initiator: it chooses the key and encrypts it to the
/// server's public key.
fn initiate(
    group: &Value,
    t: &Value,
    rng: &mut dyn Random,
) -> Result<Value, Error> {
    let key = PublicKey::try_new(&hex(t, "serverN")?, &hex(t, "serverE")?)?;
    let k = match opt_hex(t, "iutK")? {
        Some(k) => k,
        None => {
            let mut k = vec![0u8; int(group, "l")? as usize / 8];
            rng.fill(&mut k)?;
            k
        }
    };
    let label = label(group, t)?;
    let mut rng = Rng(rng);
    let c = if sha1(group)? {
        key.encrypt_oaep::<Sha1, _>(&mut rng, &label, &k)?
    } else {
        key.encrypt_oaep::<Sha512, _>(&mut rng, &label, &k)?
    };
    let c = c.as_ref();
    Ok(json!({
        "iutC": hex_value(c),
        "dkm": hex_value(&k),
        "tag": hex_value(&tag(group, &k, c)?),
    }))
}

/// Checks an answered case against the file. A responder's answers
/// must match it field for field. An initiator's ciphertext came
/// from a fresh OAEP seed, so instead it must decrypt, under the
/// server's private key the file records, to the keying material
/// the file has, and its tag must be the file's MAC with the file's
/// ciphertext replaced by the answered one.
pub fn verify(
    vendored_group: &Value,
    vendored_test: &Value,
    _answered_group: &Value,
    answered_test: &Value,
) -> Result<(), Error> {
    let same = |name: &str| -> Result<(), Error> {
        let answered = hex(answered_test, name)?;
        if answered != hex(vendored_test, name)? {
            return Err(Error::new(format!(
                "{name}: answered {}, file has {}",
                answered_test[name], vendored_test[name]
            )));
        }
        Ok(())
    };
    same("dkm")?;
    if text(vendored_group, "kasRole")? == "responder" {
        return same("tag");
    }
    let key = PrivateKey::try_new(
        &hex(vendored_test, "serverN")?,
        &hex(vendored_test, "serverE")?,
        &hex(vendored_test, "serverD")?,
    )?;
    let c = hex(answered_test, "iutC")?;
    let label = label(vendored_group, vendored_test)?;
    let k = recover(vendored_group, &key, &label, &c)?;
    if k != hex(vendored_test, "dkm")? {
        return Err(Error::new("iutC does not decrypt to the file's dkm"));
    }
    // The file's MAC input ends with its own ciphertext; the answered
    // tag must be over the same prefix and the answered one.
    let data = hex(vendored_test, "macData")?;
    let prefix = data
        .strip_suffix(&hex(vendored_test, "iutC")?[..])
        .ok_or_else(|| Error::new("macData does not end with iutC"))?;
    let mut data = prefix.to_vec();
    data.extend_from_slice(&c);
    let tag = mac_over(vendored_group, &hex(vendored_test, "macKey")?, &data)?;
    if tag != hex(answered_test, "tag")? {
        return Err(Error::new("tag is not the MAC over the answered iutC"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{find, fixed_rng};
    use super::*;
    use crate::support::list;

    #[test]
    fn initiator_without_a_key_chooses_one() {
        let Some(mut doc) = super::super::vendored(find("KTS-IFC")[0]) else {
            return;
        };
        for group in doc["testGroups"].as_array_mut().unwrap() {
            for t in group["tests"].as_array_mut().unwrap() {
                t.as_object_mut().unwrap().remove("iutK");
            }
        }
        let answered = answer(&doc, &mut fixed_rng()).unwrap();
        let mut initiated = 0;
        for (g, a) in list(&doc, "testGroups")
            .unwrap()
            .iter()
            .zip(list(&answered, "testGroups").unwrap())
        {
            if g["kasRole"] != "initiator" {
                continue;
            }
            for (t, at) in list(g, "tests")
                .unwrap()
                .iter()
                .zip(list(a, "tests").unwrap())
            {
                let dkm = hex(at, "dkm").unwrap();
                assert_ne!(dkm, hex(t, "dkm").unwrap());
                let key = PrivateKey::try_new(
                    &hex(t, "serverN").unwrap(),
                    &hex(t, "serverE").unwrap(),
                    &hex(t, "serverD").unwrap(),
                )
                .unwrap();
                let c = hex(at, "iutC").unwrap();
                let label = label(g, t).unwrap();
                assert_eq!(recover(g, &key, &label, &c).unwrap(), dkm);
                assert_eq!(hex(at, "tag").unwrap(), tag(g, &dkm, &c).unwrap());
                initiated += 1;
            }
        }
        assert!(initiated > 0);
    }

    /// The server's groups name no mode; the file's groups do, and a
    /// group in another mode is skipped.
    #[test]
    fn mode_is_optional_and_checked_when_given() {
        let Some(mut doc) = super::super::vendored(find("KTS-IFC")[0]) else {
            return;
        };
        let groups = doc["testGroups"].as_array_mut().unwrap();
        groups.truncate(1);
        let group = groups[0].as_object_mut().unwrap();
        group.remove("kasMode");
        assert_eq!(skip_reason(&doc["testGroups"][0]).unwrap(), None);
        let answered = answer(&doc, &mut fixed_rng()).unwrap();
        assert!(answered["testGroups"][0]["tests"][0].get("dkm").is_some());

        doc["testGroups"][0]["kasMode"] = json!("kdfKc");
        let why = skip_reason(&doc["testGroups"][0]).unwrap().unwrap();
        assert!(why.starts_with("kdfKc"));
    }
}
