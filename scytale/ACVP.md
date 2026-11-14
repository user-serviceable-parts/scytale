# ACVP results

ACVP is NIST's [Automated Cryptographic Validation Protocol][acvp]:
a NIST server issues test vectors for an algorithm, the
implementation answers them, and the server judges the answers. It
is the testing that stands behind a CAVP algorithm validation. The
vectors and the server are published in NIST's
[ACVP-Server][server] repository.

This file records the latest run of scytale against NIST's
demonstration server. It is a real session, judged by NIST, but the
demonstration server issues no certificates: this is not a CAVP
validation, and scytale has none. Each new run replaces this record.

ACVP tests only the algorithms NIST specifies, so the library's
other algorithms are not here; the crate's README says how those
are tested.

## The run

| | |
| --- | --- |
| Date | 2026-11-14 |
| Server | `demo.acvts.nist.gov`, session 788120 |
| Result | 88 vector sets, 88 passed |
| Commit | `ea15cb3` |

## Operating environment

| | |
| --- | --- |
| Processor | 13th Gen Intel Core i7-1355U, x86-64 |
| Operating system | Debian GNU/Linux 13, Linux 6.12 |
| Compiler | rustc 1.99.1, release build |
| Dispatch | the implementations the library picks on this processor |

## What passed

| Algorithm | Mode | Revision | Result |
| --- | --- | --- | --- |
| ACVP-AES-CBC |  | 1.0 | passed |
| ACVP-AES-CCM |  | 1.0 | passed |
| ACVP-AES-CFB1 |  | 1.0 | passed |
| ACVP-AES-CFB128 |  | 1.0 | passed |
| ACVP-AES-CFB8 |  | 1.0 | passed |
| ACVP-AES-CTR |  | 1.0 | passed |
| ACVP-AES-ECB |  | 1.0 | passed |
| ACVP-AES-FF1 |  | 1.0 | passed |
| ACVP-AES-GCM |  | 1.0 | passed |
| ACVP-AES-GCM-SIV |  | 1.0 | passed |
| ACVP-AES-GMAC |  | 1.0 | passed |
| ACVP-AES-KW |  | 1.0 | passed |
| ACVP-AES-KWP |  | 1.0 | passed |
| ACVP-AES-OFB |  | 1.0 | passed |
| ACVP-AES-XPN |  | 1.0 | passed |
| ACVP-AES-XTS |  | 2.0 | passed |
| HMAC-SHA2-224 |  | 1.0 | passed |
| HMAC-SHA2-256 |  | 1.0 | passed |
| HMAC-SHA2-384 |  | 1.0 | passed |
| HMAC-SHA2-512 |  | 1.0 | passed |
| HMAC-SHA2-512/224 |  | 1.0 | passed |
| HMAC-SHA2-512/256 |  | 1.0 | passed |
| HMAC-SHA3-224 |  | 1.0 | passed |
| HMAC-SHA3-256 |  | 1.0 | passed |
| HMAC-SHA3-384 |  | 1.0 | passed |
| HMAC-SHA3-512 |  | 1.0 | passed |
| HMAC-SHA-1 |  | 1.0 | passed |
| PBKDF |  | 1.0 | passed |
| SHA2-224 |  | 1.0 | passed |
| SHA2-256 |  | 1.0 | passed |
| SHA2-384 |  | 1.0 | passed |
| SHA2-512 |  | 1.0 | passed |
| SHA2-512/224 |  | 1.0 | passed |
| SHA2-512/256 |  | 1.0 | passed |
| SHA3-224 |  | 2.0 | passed |
| SHA3-256 |  | 2.0 | passed |
| SHA3-384 |  | 2.0 | passed |
| SHA3-512 |  | 2.0 | passed |
| SHAKE-128 |  | 1.0 | passed |
| SHAKE-256 |  | 1.0 | passed |
| CMAC-AES |  | 1.0 | passed |
| DetECDSA | sigGen | FIPS186-5 | passed |
| ECDSA | keyGen | FIPS186-5 | passed |
| ECDSA | keyVer | FIPS186-5 | passed |
| ECDSA | sigGen | FIPS186-5 | passed |
| ECDSA | sigVer | FIPS186-5 | passed |
| EDDSA | keyGen | 1.0 | passed |
| EDDSA | keyVer | 1.0 | passed |
| EDDSA | sigGen | 1.0 | passed |
| EDDSA | sigVer | 1.0 | passed |
| KDA | HKDF | Sp800-56Cr2 | passed |
| KDA | OneStep | Sp800-56Cr2 | passed |
| KDA | OneStepNoCounter | Sp800-56Cr2 | passed |
| KDF |  | 1.0 | passed |
| KDF | KMAC | Sp800-108r1 | passed |
| KMAC-128 |  | 1.0 | passed |
| KMAC-256 |  | 1.0 | passed |
| KTS-IFC |  | Sp800-56Br2 | passed |
| LMS | keyGen | 1.0 | passed |
| LMS | sigGen | SP800-208 | passed |
| LMS | sigVer | SP800-208 | passed |
| ML-DSA | keyGen | FIPS204 | passed |
| ML-DSA | sigGen | FIPS204-tr1 | passed |
| ML-DSA | sigVer | FIPS204 | passed |
| ML-KEM | encapDecap | FIPS203-tr1 | passed |
| ML-KEM | keyGen | FIPS203 | passed |
| RSA | keyGen | FIPS186-5 | passed |
| RSA | sigGen | FIPS186-5 | passed |
| RSA | sigVer | FIPS186-4 | passed |
| RSA | sigVer | FIPS186-5 | passed |
| RSA | signaturePrimitive | 2.0 | passed |
| RSA | decryptionPrimitive | 1.0 | passed |
| SLH-DSA | keyGen | FIPS205 | passed |
| SLH-DSA | sigGen | FIPS205 | passed |
| SLH-DSA | sigVer | FIPS205 | passed |
| TLS-v1.2 | KDF | RFC7627 | passed |
| TupleHash-128 |  | 1.0 | passed |
| TupleHash-256 |  | 1.0 | passed |
| XECDH | SSC | RFC7748 | passed |
| XECDH | keyGen | RFC7748 | passed |
| cSHAKE-128 |  | 1.0 | passed |
| cSHAKE-256 |  | 1.0 | passed |
| ctrDRBG |  | 1.0 | passed |
| hashDRBG |  | 1.0 | passed |
| hashDRBG |  | SP800-90Ar1 | passed |
| hmacDRBG |  | 1.0 | passed |
| hmacDRBG |  | SP800-90Ar1 | passed |
| kdf-components | ansix9.63 | 1.0 | passed |

[acvp]: https://pages.nist.gov/ACVP/
[server]: https://github.com/usnistgov/ACVP-Server
