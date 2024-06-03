use core::{ops::Mul, panic};
use crypto_bigint::{Random, U2048};
use crypto_bigint::{Uint, Zero, U4096};
use crypto_primes::generate_safe_prime;
use hex_literal::hex;
use hkdf::Hkdf;
use num_bigint::{traits::ModInverse, BigInt, IntoBigUint};
use num_bigint::{BigUint, RandomBits};
use num_traits::ops::bytes;
use num_traits::{CheckedSub, One, ToBytes};
use rand::distributions::Distribution;
use rand::seq::index;
use rand::{self, CryptoRng, Rng};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384};
use std::io::Read;
use std::vec;

const em_bits: usize = 2048usize;
const s_len: usize = 48usize; // Salt length

#[derive(Clone, Debug)]
pub struct PrivateKey {
    n: BigUint,
    p: BigUint,
    q: BigUint,
    phi: BigUint,
    d: BigUint,
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    n: BigUint,
    e: BigUint,
}

/*
/// Inputs:
/// - bits, length in bits of the RSA modulus, a multiple of 2
///
/// Outputs:
/// - sk, metadata-specific private key (n, p, q, phi, d)
/// - pk, metadata-specific public key (n, e)
///
/// Steps:
/// 1. p = SafePrime(bits / 2)
/// 2. q = SafePrime(bits / 2)
/// 3. while p == q, go to step 2.
/// 4. phi = (p - 1) * (q - 1)
/// 5. e = 65537
/// 6. d = inverse_mod(e, phi)
/// 7. n = p * q
/// 7. sk = (n, p, q, phi, d)
/// 8. pk = (n, e)
/// 9. output (sk, pk)
pub fn key_gen() -> (PrivateKey, PublicKey) {
    // let mut rng = rand::thread_rng();
    /*let first_prime: Uint<16> = generate_safe_prime(Some(1024));
    let p_bytes = first_prime.to_string();
    let mut bytes = [0u8; 128];
    hex::decode_to_slice(p_bytes, &mut bytes as &mut [u8]).unwrap();
    println!("p: {:#02x?}", bytes);*/
    let bytes = [
        0xcc, 0xda, 0xf, 0x40, 0xa, 0xe5, 0xe9, 0xba, 0x68, 0x4a, 0xb, 0xab, 0x10, 0x19, 0x4e,
        0xf3, 0x5e, 0xd, 0xdc, 0xf7, 0x29, 0x9d, 0xc0, 0x29, 0x9c, 0xe8, 0xc1, 0xfd, 0xa6, 0x8e,
        0x73, 0xc, 0x68, 0x1a, 0x1c, 0xa8, 0x94, 0xa5, 0x5, 0xd8, 0x76, 0xfc, 0x9e, 0x2, 0xc9,
        0x2f, 0x34, 0xd4, 0x8e, 0x86, 0x8f, 0x4e, 0x87, 0x30, 0x27, 0xf6, 0x4b, 0xf4, 0xa1, 0x71,
        0x7b, 0xdb, 0x8c, 0x2f, 0x82, 0xff, 0xcb, 0x52, 0xaf, 0xe2, 0xd5, 0x71, 0x4d, 0x7e, 0x8e,
        0x66, 0xc3, 0x88, 0x5c, 0x3d, 0x8b, 0x5, 0x7c, 0x7c, 0xd8, 0x8f, 0x71, 0x4c, 0xc4, 0xde,
        0x2d, 0x55, 0xa3, 0x8c, 0x73, 0x1d, 0xea, 0xad, 0xc6, 0x3b, 0x6a, 0xf, 0x6c, 0x5a, 0xdd,
        0x7c, 0x1a, 0xdd, 0x81, 0x86, 0x2c, 0xfa, 0x74, 0x82, 0x3e, 0x80, 0x46, 0x15, 0x36, 0x84,
        0xb8, 0x8a, 0xf, 0x3d, 0x5, 0x8e, 0x4, 0xb,
    ];
    let p: BigUint = BigUint::from_bytes_be(&bytes);

    /*let second_prime: Uint<16> = generate_safe_prime(Some(1024));
    let q_bytes = second_prime.to_string();
    let mut bytes = [0u8; 128];
    hex::decode_to_slice(q_bytes, &mut bytes as &mut [u8]).unwrap();
    println!("q: {:#02x?}", bytes);*/
    let bytes = [
        0xd6, 0x9f, 0xf0, 0xe1, 0x6c, 0x57, 0x12, 0x53, 0x2d, 0x25, 0x25, 0xe6, 0x9c, 0xd4, 0x23,
        0xe5, 0x4c, 0x14, 0xb7, 0x48, 0xee, 0x8b, 0xc0, 0x1f, 0xc0, 0x9b, 0x8e, 0x33, 0x1e, 0x8d,
        0xbe, 0x72, 0xeb, 0x9d, 0x68, 0x1, 0xcd, 0x9b, 0xf3, 0x7e, 0x96, 0xcb, 0xc1, 0x65, 0x7b,
        0xf7, 0x29, 0x1, 0xcd, 0xd8, 0x4d, 0x94, 0x7d, 0xd2, 0xe3, 0xdd, 0xfd, 0xf5, 0x7a, 0x94,
        0xd3, 0x39, 0x2b, 0x7b, 0x31, 0xdd, 0x37, 0xf, 0x8a, 0x4e, 0x50, 0x67, 0x3e, 0x19, 0xdc,
        0x62, 0x5, 0x22, 0x43, 0xa, 0x57, 0x5c, 0x6c, 0xcb, 0xae, 0x2a, 0xa1, 0xcf, 0xb2, 0x4f,
        0x1b, 0x2, 0x6c, 0xee, 0x61, 0x81, 0x2d, 0x26, 0x4f, 0xa4, 0xa6, 0x9e, 0x17, 0x86, 0xb,
        0x94, 0x45, 0x24, 0x32, 0x38, 0xcf, 0xc3, 0x1b, 0x66, 0xaf, 0x36, 0xf7, 0xa5, 0x15, 0xa7,
        0xfc, 0xc5, 0xb7, 0xe0, 0xeb, 0xb1, 0xa9, 0xe7,
    ];
    let q: BigUint = BigUint::from_bytes_be(&bytes);

    // let mut count = 0u8;
    // while p == q && count != 100 {
    //     p = BigUint::from_bytes_be(&generate_safe_prime(Some(em_bits / 2)).to_string().as_bytes());
    //     q = BigUint::from_bytes_be(&generate_safe_prime(Some(em_bits / 2)).to_string().as_bytes());
    //     count = count + 1;
    // }

    let phi: BigUint = p
        .checked_sub(&BigUint::one())
        .expect("don't panic!")
        .mul(&q.checked_sub(&BigUint::one()).expect("don't panic!")); //(q.checked_sub(Uint::ONE));
    let e: BigUint = BigUint::from(65537u32); //from_be_hex("0x010001"); // BigUint::from(65537u64) in hex
    let d = e.clone().mod_inverse(&phi).unwrap(); // todo: if rc is false; we should retry
    let n = p.clone().mul(&q);
    let sk = PrivateKey {
        n: n.clone(),
        p,
        q,
        phi,
        d,
    };
    let pk = PublicKey { n, e };
    (sk, pk)
}
*/

fn mgf1(mask_len: usize, h_len: usize, mgf_seed: &[u8]) -> Vec<u8> {
    assert!(mask_len as u32 <= u32::MAX);
    let mut t: Vec<u8> = vec![];
    for i in 0..((mask_len + h_len - 1) / h_len) {
        // C = I2OSP (counter, 4)
        let c = (i as u32).to_be_bytes(); // todo le or be?

        // T = T || Hash(mgfSeed || C)
        let mut hasher = Sha384::new();
        hasher.update([mgf_seed, &c].concat());
        // hasher.update(c); // todo does this make a difference?
        t = [t, hasher.finalize().to_vec()].concat();
    }
    t[..mask_len].to_vec()
}

// https://www.rfc-editor.org/rfc/rfc8017#section-9.1.1
fn emsa_pss_encode(msg: &[u8]) -> Vec<u8> {
    if msg.len() as u64 > u64::MAX {
        // todo: max length is for 48 bytes not 64
        panic!("message too long!");
    }

    let mut hasher = Sha384::new();
    hasher.update(msg);
    let m_hash: Vec<u8> = hasher.finalize().to_vec();

    // emLen < hLen + sLen + 2
    let em_len = (em_bits - 1 + 7) / 8;
    let h_len = 48usize;
    if em_len < h_len + s_len + 2 {
        panic!("encoding error!");
    }

    // let mut rng = rand::thread_rng();
    // let salt: U256 = U256::random(&mut rng);
    // let salt: [u8; s_len] = rng.gen();
    let salt = &hex!(
        "648ea74482fbab69876817ee3c2055a6921a458648c802c09a23f8825b2
        59724e41c960ef29febe16a04e120c8b1cc1a"
    );

    let msg_prime = [
        [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8].as_slice(),
        &m_hash,
        salt,
    ]
    .concat();
    let mut hasher = Sha384::new();
    hasher.update(msg_prime);
    let msg_hash = hasher.finalize();
    let ps = vec![0u8; em_len - h_len - s_len - 2];
    // DB = PS || 0x01 || salt
    let db = [ps.as_slice(), &[1u8], salt].concat();

    // dbMask = MGF(H, emLen - hLen - 1)
    let db_mask = mgf1(em_len - h_len - 1, h_len, &msg_hash); // todo mgfseed?
                                                              // println!(
                                                              //     "ps len: {:?}, salt len: {:?}, db len: {:?}, db mask len: {:?}",
                                                              //     ps.len(),
                                                              //     salt.len(),
                                                              //     db.len(),
                                                              //     db_mask.len()
                                                              // );
                                                              // maskedDB = DB \xor dbMask
    let masked_db = db.iter().zip(db_mask.iter()).map(|(x, y)| x ^ y).collect();
    // let mut masked_db: Vec<u8> = vec![];
    // for (_, (z1, z2)) in zipped.enumerate() {
    //     masked_db.push(z1 ^ z2);
    // }

    // todo: Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero.
    // EM = maskedDB || H || 0xbc
    let em = [masked_db, msg_hash.to_vec(), vec![0xbcu8]].concat();
    return em;
}

// DerivePublicKey(pk, info)

// Parameters:
// - modulus_len, the length in bytes of the RSA modulus n
// - Hash, the hash function used to hash the message
// Inputs:
// - pk, public key (n, e)
// - info, public metadata, a byte string
// Outputs:
// - pk_derived, metadata-specific public key (n, e')
// Steps:
// 1. hkdf_input = concat("key", info, 0x00)
// 2. hkdf_salt = int_to_bytes(n, modulus_len)
// 3. lambda_len = modulus_len / 2
// 4. hkdf_len = lambda_len + 16
// 5. expanded_bytes = HKDF(IKM=hkdf_input, salt=hkdf_salt, info="PBRSA", L=hkdf_len)
// 6. expanded_bytes[0] &= 0x3F // Clear two-most top bits
// 7. expanded_bytes[lambda_len-1] |= 0x01 // Set bottom-most bit
// 8. e' = bytes_to_int(slice(expanded_bytes, 0, lambda_len))
// 9. output pk_derived = (n, e')
fn derive_public_key(pub_key: &PublicKey, info: &[u8]) -> PublicKey {
    let hkdf_input = ["key".as_bytes(), info, &[0u8]].concat();
    let hkdf_salt = pub_key.n.to_bytes_be();
    const LAMBDA_LEN: usize = em_bits / 2 / 8;
    const HKDF_LEN: usize = LAMBDA_LEN + 16;
    let hkdf = Hkdf::<Sha384>::new(Some(&hkdf_salt), &hkdf_input);
    let mut expanded_bytes = [0u8; HKDF_LEN];
    hkdf.expand("PBRSA".as_bytes(), expanded_bytes.as_mut_slice())
        .unwrap();
    expanded_bytes[0] &= 0x3F;
    expanded_bytes[LAMBDA_LEN - 1] |= 0x01;

    let e_prime = BigUint::from_bytes_be(&expanded_bytes[..LAMBDA_LEN]); // or LAMBDA_LEN +1; bug in the spec?

    PublicKey {
        n: pub_key.n.clone(),
        e: e_prime,
    }
}

// 1.  If the signature representative s is not between 0 and n - 1, output "signature representative out of range" and stop.
// 2.  Let m = s^e mod n.
// 3.  Output m.
fn rsavp1(pub_key: &PublicKey, s: &BigUint) -> BigUint {
    if s.cmp(&pub_key.n).is_gt() {
        panic!("signature representative out of range");
    }

    s.modpow(&pub_key.e, &pub_key.n)
}

// 1.  If the message representative m is not between 0 and n - 1,
//     output "message representative out of range" and stop.
// 2.  The signature representative s is computed as follows.
//     a.  If the first form (n, d) of K is used, let s = m^d mod n.
//     b.  If the second form (p, q, dP, dQ, qInv) and (r_i, d_i,
//         t_i) of K is used, proceed as follows:
//         1.  Let s_1 = m^dP mod p and s_2 = m^dQ mod q.
//         2.  If u > 2, let s_i = m^(d_i) mod r_i, i = 3, ..., u.
//         3.  Let h = (s_1 - s_2) * qInv mod p.
//         4.  Let s = s_2 + q * h.
//         5.  If u > 2, let R = r_1 and for i = 3 to u do
//             a.  Let R = R * r_(i-1).
//             b.  Let h = (s_i - s) * t_i mod r_i.
//             c.  Let s = s + R * h.
// 3.  Output s.
fn rsasp1(priv_key: &PrivateKey, msg: &BigUint) -> BigUint {
    // todo: 1.  If the message representative m is not between 0 and n - 1,
    // let s = msg.modpow(&priv_key.d.to_biguint().unwrap(), &priv_key.n); // todo: type mismatch
    let s = msg.modpow(&priv_key.d, &priv_key.n); // todo: type mismatch
    s
}

/// 1. msg_prime = concat("msg", int_to_bytes(len(info), 4), info, msg)
/// 2. encoded_msg = EMSA-PSS-ENCODE(msg_prime, bit_len(n))
/// with Hash, MGF, and salt_len as defined in the parameters
/// 3. If EMSA-PSS-ENCODE raises an error, raise the error and stop
/// 4. m = bytes_to_int(encoded_msg)
/// 5. c = is_coprime(m, n)
/// 6. If c is false, raise an "invalid input" error
/// and stop
/// 7. r = random_integer_uniform(1, n)
/// 8. inv = inverse_mod(r, n)
/// 9. If inverse_mod fails, raise an "blinding error" error
/// and stop
/// 10. pk_derived = DerivePublicKey(pk, info)
/// 11. x = RSAVP1(pk_derived, r)
/// 12. z = m * x mod n
/// 13. blinded_msg = int_to_bytes(z, modulus_len)
/// 14. output blinded_msg, inv
pub fn blind(pub_key: &PublicKey, msg: &[u8], info: &[u8]) -> (Vec<u8>, BigUint) {
    let pk_derived = derive_public_key(&pub_key, info);
    let info_len: [u8; 4] = (info.len() as u32).to_be_bytes();
    let msg_prime = ["msg".as_bytes(), &info_len, info, msg].concat();

    let encode_msg = emsa_pss_encode(msg_prime.as_slice());
    // println!("encoded message: {:?}", encode_msg.len());

    let m = BigUint::from_bytes_be(&encode_msg);
    // 5. c = is_coprime(m, n)
    // 6. If c is false, raise an "invalid input" error and stop

    /*let mut rng = rand::thread_rng();
    // let n = crypto_bigint::NonZero::<BigUint>::new(pub_key.n).unwrap();
    let r: BigUint = RandomBits::new(2048).sample(&mut rng);
    println!("r: {:#x}", r);
    // let r = r % &pub_key.n;
    // println!("r: {:#x}", r);
    let r_inverse = r.clone().mod_inverse(&pub_key.n).expect("blinding error");*/

    // todo: only for testing
    let r = BigUint::from_bytes_be(&hex!(
        "d55491221c9a9ce5687b84669880abbc4db57c8f82864a450a5bf7c3f0
        902884fa418c74bf663f3bfcff74a4792356f3ce052f128b084f8b028cf432533
        27514f4b38430c69f19f155634429803badd1f6849d8603882eb9b648b697cb2f
        2c4069b504562e19bb9f1cf99da47c198c2ae04f4bd3add78025e80f146edce48
        dc3e9dc0ba3ee14bc97489050e26dc8935f3ecfcaea07c9c1a3d8e41be1e49dc8
        aa171ac4cec9d1cddd8066b13767901dcb339e2cce40d11f5cff6c870012bca49
        109ce6e81e165d3831531cbf8503f3cfde68340789979cba96602e70613a13869
        aff57f2170e31ebe85564e3f026d8cd1835e59144fb8c008391c55d2fb1a5488"
    ));
    let r = r.clone() % pub_key.clone().n;
    let r_temp = r.clone().mod_inverse(pub_key.clone().n).unwrap();
    // borrowed code from RSA crate
    let r_inverse = r_temp.into_biguint().unwrap();
    let x = rsavp1(&pk_derived, &r);
    /*
    // let mut rng = rand::thread_rng();
    // let r = U4096::random(&mut rng);
    let r = r.add_mod(&U4096::ZERO, &biguint_to_u4096(pub_key.clone().n));
    let r_inv = r.inv_mod(&biguint_to_u4096(pub_key.clone().n)).0;
    let r_inverse = u4096_to_biguint(r_inv);

    let pk_derived = derive_public_key(&pub_key, info);
    let x = rsavp1(&pk_derived, &u4096_to_biguint(r));*/
    let z = (m * x) % &pub_key.n;
    let blinded_msg = z.to_bytes_be();
    // println!("blinded msg len: {:?}", blinded_msg.len());
    (blinded_msg, r_inverse)
}

// Steps:
// 1. (n, e') = DerivePublicKey(n, info)
// 2. d' = inverse_mod(e', phi)
// 3. sk_derived = (n, p, q, phi, d')
// 4. pk_derived = (n, e')
// 5. Output (sk_derived, pk_derived)
fn derive_key_pair(
    priv_key: PrivateKey,
    pub_key: &PublicKey,
    info: &[u8],
) -> (PrivateKey, PublicKey) {
    let pub_key_derived = derive_public_key(pub_key, info);

    let d_prime = pub_key_derived
        .clone()
        .e
        .mod_inverse(priv_key.clone().phi)
        .unwrap()
        .into_biguint()
        .unwrap();

    let priv_key_derived = PrivateKey {
        n: priv_key.n,
        p: priv_key.p,
        q: priv_key.q,
        phi: priv_key.phi,
        d: d_prime,
    };
    (priv_key_derived, pub_key_derived)
}

// Steps:
// 1. m = bytes_to_int(blind_msg)
// 2. sk_derived, pk_derived = DeriveKeyPair(sk, info)
// 3. s = RSASP1(sk_derived, m)
// 4. m' = RSAVP1(pk_derived, s)
// 5. If m != m', raise "signing failure" and stop
// 6. blind_sig = int_to_bytes(s, modulus_len)
// 7. output blind_sig
pub fn blind_sign(
    priv_key: &PrivateKey,
    pub_key: &PublicKey,
    blind_msg: &[u8],
    info: &[u8],
) -> Vec<u8> {
    let m = BigUint::from_bytes_be(blind_msg);
    let (priv_key_derived, pub_key_derived) = derive_key_pair(priv_key.clone(), pub_key, info); // todo
    let s = rsasp1(&priv_key_derived, &m);
    let m_prime = rsavp1(&pub_key_derived, &s);
    assert_eq!(m, m_prime);
    let blind_sig = s.to_bytes_be();
    blind_sig
}

// Finalize(pk, msg, info, blind_sig, inv)

// Parameters:
// - modulus_len, the length in bytes of the RSA modulus n
// - Hash, the hash function used to hash the message
// - MGF, the mask generation function
// - salt_len, the length in bytes of the salt

// Inputs:
// - pk, public key (n, e)
// - msg, message to be signed, a byte string
// - info, public metadata, a byte string
// - blind_sig, signed and blinded element, a byte string of
//   length modulus_len
// - inv, inverse of the blind, an integer

// Outputs:
// - sig, a byte string of length modulus_len

// Errors:
// - "invalid signature": Raised when the signature is invalid
// - "unexpected input size": Raised when a byte string input doesn't
//   have the expected length.

// Steps:
// 1. If len(blind_sig) != modulus_len, raise "unexpected input size" and stop
// 2. z = bytes_to_int(blind_sig)
// 3. s = z * inv mod n
// 4. sig = int_to_bytes(s, modulus_len)
// 5. msg_prime = concat("msg", int_to_bytes(len(info), 4), info, msg)
// 6. pk_derived = DerivePublicKey(pk, info)
// 7. result = RSASSA-PSS-VERIFY(pk_derived, msg_prime, sig) with
//    Hash, MGF, and salt_len as defined in the parameters
// 8. If result = "valid signature", output sig, else
//    raise "invalid signature" and stop
pub fn finalize(
    pub_key: &PublicKey,
    msg: &[u8],
    info: &[u8],
    blind_sig: &[u8],
    blind_inv: &BigUint,
) -> Vec<u8> {
    // todo: add step 1
    let z = BigUint::from_bytes_be(blind_sig);
    let s = z * blind_inv % &pub_key.n;
    let sig = s; // todo is it really necessary when rsa_pss_verify() converts it back
                 // todo return the sig to compare it with the expected sig

    /*
    let info_len: [u8; 4] = (info.len() as u32).to_be_bytes();
    let msg_prime = ["msg".as_bytes(), &info_len, info, msg].concat();
    // let pk_derived = derive_public_key(&pub_key, &info);
    // let result = rsa_pss_verify(&pk_derived, &msg_prime, &sig);
    let result = rsa_pss_verify(&pub_key, &msg, &sig);
    if (!result) {
        panic!("Failed to verify!");
    }
    */
    sig.to_bytes_be()
}

fn rsa_pss_verify(pub_key: &PublicKey, msg: &[u8], sig: &BigUint) -> bool {
    // 1.  Length checking: If the length of the signature S is not k
    //       octets, output "invalid signature" and stop.
    let m = rsavp1(pub_key, &sig);
    // let em = m.to_bytes_be();
    emsa_pss_verify(msg, &m) // todo same here, no need to convert
}

// https://www.rfc-editor.org/rfc/rfc8017#section-9.1.2
fn emsa_pss_verify(msg: &[u8], em: &BigUint) -> bool {
    // 1.   If the length of M is greater than the input limitation for
    //        the hash function (2^61 - 1 octets for SHA-1), output
    //        "inconsistent" and stop.
    let mut hasher = Sha384::new();
    hasher.update(msg);
    let msg_hash = hasher.finalize();
    // 3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    // 4.   If the rightmost octet of EM does not have hexadecimal value
    // 0xbc, output "inconsistent" and stop.
    let em_len = (em_bits - 1 + 7) / 8;
    let h_len = 48usize;
    let masked_db: Vec<u8> = em.to_bytes_be().as_slice()[..em_len - h_len - 1].to_vec();
    let h = em.to_bytes_be().as_slice()[(em_len - h_len)..].to_vec();

    // 6.   If the leftmost 8emLen - emBits bits of the leftmost octet in
    //        maskedDB are not all equal to zero, output "inconsistent" and
    //        stop.
    // println!(
    //     "mgf1 inputs: 1: {:?},\n 2: {:?},\n 3: {:?}",
    //     em_len - h_len - 1,
    //     h_len,
    //     h
    // );
    let db_mask = mgf1(em_len - h_len - 1, h_len, &h);
    // println!("h len: {:?}, other: {:?}", masked_db.len(), db_mask.len());
    let db: Vec<u8> = db_mask
        .iter()
        .zip(masked_db.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    // println!(
    //     "db mask len: {:?}, mask len: {:?}, position: {:?}, db at position: {:?}",
    //     db_mask.len(),
    //     masked_db.len(),
    //     em_len - h_len - s_len - 2,
    //     db[em_len - h_len - s_len - 2]
    // );
    // 9.   Set the leftmost 8emLen - emBits bits of the leftmost octet
    //        in DB to zero.
    // 10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not
    //        zero or if the octet at position emLen - hLen - sLen - 1 (the
    //        leftmost position is "position 1") does not have hexadecimal
    //        value 0x01, output "inconsistent" and stop.
    // println!("final db: {:x?}", db);
    let salt: Vec<u8> = db[s_len..].to_vec();
    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
    let m_prime = [
        [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8].to_vec(),
        msg_hash.to_vec(),
        salt,
    ]
    .concat();
    let mut hasher = Sha384::new();
    hasher.update(m_prime);
    let h_prime = hasher.finalize();
    for index in 0..h.len() {
        if h[index] != h_prime[index] {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::panic::PanicInfo;

    use rsa::pss::Signature;

    use super::*;

    #[test]
    fn test_vector_one() {
        // Test vector 1
        let p: BigUint = BigUint::from_bytes_be(&hex!(
            "dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a332\
            4c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf616\
            8ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c5\
            5f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3"
        ));

        let q: BigUint = BigUint::from_bytes_be(&hex!(
            "f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56f\
            a8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db\
            5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b\
            651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3"
        ));

        let d: BigUint = BigUint::from_bytes_be(&hex!(
            "4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc522154\
            94981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e305\
            1b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc\
            000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62\
            ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa\
            4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a1\
            8d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4\
            abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d"
        ));

        let e: BigUint = BigUint::from_bytes_be(&hex!("010001"));

        let n: BigUint = BigUint::from_bytes_be(&hex!(
            "d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69\
            821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd5\
            5f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75\
            e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710\
            f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61b\
            c7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366\
            a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725\
            cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9"
        ));

        let priv_key = PrivateKey {
            n: n.clone(),
            p: p.clone(),
            q: q.clone(),
            phi: (p - BigUint::one()) * (q - BigUint::one()),
            d: d,
        };

        let pub_key = PublicKey { n, e };

        let msg = hex::decode("68656c6c6f20776f726c64").unwrap();

        let info = hex::decode("6d65746164617461").unwrap();

        let (blinded_msg, inv_blind) = blind(&pub_key, &msg, &info);

        let eprime: BigUint = BigUint::from_bytes_be(&hex!(
            "30581b1adab07ac00a5057e2986f37caaa68ae963ffbc4d36c16ea5f3\
            689d6f00db79a5bee56053adc53c8d0414d4b754b58c7cc4abef99d4f0d0b2e29\
            cbddf746c7d0f4ae2690d82a2757b088820c0d086a40d180b2524687060d768ad\
            5e431732102f4bc3572d97e01dcd6301368f255faae4606399f91fa913a6d699d\
            6ef1"
        ));

        // add an assert here for e_prime
        // println!("expected eprime: {:?}", eprime);

        let _r: BigUint = BigUint::from_bytes_be(
            b"d55491221c9a9ce5687b84669880abbc4db57c8f82864a450a5bf7c3f0
            902884fa418c74bf663f3bfcff74a4792356f3ce052f128b084f8b028cf432533
            27514f4b38430c69f19f155634429803badd1f6849d8603882eb9b648b697cb2f
            2c4069b504562e19bb9f1cf99da47c198c2ae04f4bd3add78025e80f146edce48
            dc3e9dc0ba3ee14bc97489050e26dc8935f3ecfcaea07c9c1a3d8e41be1e49dc8
            aa171ac4cec9d1cddd8066b13767901dcb339e2cce40d11f5cff6c870012bca49
            109ce6e81e165d3831531cbf8503f3cfde68340789979cba96602e70613a13869
            aff57f2170e31ebe85564e3f026d8cd1835e59144fb8c008391c55d2fb1a5488",
        );

        let _salt: BigUint = BigUint::from_bytes_be(
            b"648ea74482fbab69876817ee3c2055a6921a458648c802c09a23f8825b2
            59724e41c960ef29febe16a04e120c8b1cc1a",
        );

        let expected_blind_msg = &hex!(
            "cfd613e27b8eb15ee0b1df0e1bdda7809a61a29e9b6e9f3ec7c3
            45353437638e85593a7309467e36396b0515686fe87330b312b6f89df26dc1cc8
            8dd222186ca0bfd4ffa0fd16a9749175f3255425eb299e1807b76235befa57b28
            f50db02f5df76cf2f8bcb55c3e2d39d8c4b9a0439e71c5362f35f3db768a5865b
            864fdf979bc48d4a29ae9e7c2ea259dc557503e2938b9c3080974bd86ad8b0daa
            f1d103c31549dcf767798079f88833b579424ed5b3d700162136459dc29733256
            f18ceb74ccf0bc542db8829ca5e0346ad3fe36654715a3686ceb69f73540efd20
            530a59062c13880827607c68d00993b47ad6ba017b95dfc52e567c4bf65135072
            b12a4"
        );

        assert_eq!(blinded_msg, expected_blind_msg);

        let blind_sig = blind_sign(&priv_key, &pub_key, &blinded_msg, &info);

        let expected_blind_sig = hex!(
            "ca7d4fd21085de92b514fbe423c5745680cace6ddfa864a9bd97
            d29f3454d5d475c6c1c7d45f5da2b7b6c3b3bc68978bb83929317da25f491fee8
            6ef7e051e7195f3558679b18d6cd3788ac989a3960429ad0b7086945e8c4d38a1
            b3b52a3903381d9b1bf9f3d48f75d9bb7a808d37c7ecebfd2fea5e89df59d4014
            a1a149d5faecfe287a3e9557ef153299d49a4918a6dbdef3e086eeb264c0c3621
            bcd73367195ae9b14e67597eaa9e3796616e30e264dc8c86897ae8a6336ed2cd9
            3416c589a058211688cf35edbd22d16e31c28ff4a5c20f1627d09a71c71af372e
            dc18d2d7a6e39df9365fe58a34605fa1d9dc53efd5a262de849fb083429e20586
            e210e"
        );

        assert_eq!(blind_sig, expected_blind_sig);

        let expected_sig = hex!(
            "cdc6243cd9092a8db6175b346912f3cc55e0cf3e842b4582802358dddf6f
            61decc37b7a9ded0a108e0c857c12a8541985a6efad3d17f7f6cce3b5ee20016e
            5c36c7d552c8e8ff6b5f3f7b4ed60d62eaec7fc11e4077d7e67fc6618ee092e20
            05964b8cf394e3e409f331dca20683f5a631b91cae0e5e2aa89eeef4504d24b45
            127abdb3a79f9c71d2f95e4d16c9db0e7571a7f524d2f64438dfb32001c00965f
            f7a7429ce7d26136a36ebe14644559d3cefc477859dcd6908053907b325a34aaf
            654b376fade40df4016ecb3f5e1c89fe3ec500a04dfe5c8a56cad5b086047d2f9
            63ca73848e74cf24bb8bf1720cc9de4c78c64449e8af3e7cddb0dab1821998"
        );

        let sig = finalize(&pub_key, &msg, &info, &blind_sig, &inv_blind);
        assert_eq!(sig, expected_sig);

        // use RSA crate's verify function for now...
        use rsa::pss::VerifyingKey;
        use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
        use rsa::RsaPrivateKey;

        let rsa_public_key = RsaPublicKey::new(pub_key.n, pub_key.e).unwrap();
        let verifying_key = VerifyingKey::<Sha384>::new(rsa_public_key);
        let sig: Signature = sig.as_slice().try_into().unwrap();
        // Verify
        // assert!(verifying_key.verify(&msg, &sig).is_ok());
    }
}
