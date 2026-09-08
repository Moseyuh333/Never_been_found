//! Adapter ML-KEM-768 (FIPS 203). Mọi phụ thuộc crate ml-kem gói vào đây:
//! nếu API lệch phiên bản chỉ cần sửa file này, phần còn lại của dự án không đổi.

use crate::{CryptoError, CT_LEN, KEM_PK_LEN};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::CryptoRngCore;

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
/// Kiểu khóa mở (decapsulation tạo từ `kem_generate`) — public để lưu trong struct.
pub type DecapsKey = <MlKem768 as KemCore>::DecapsulationKey;
type Ct = ml_kem::Ciphertext<MlKem768>;
type Ss = ml_kem::SharedKey<MlKem768>;

fn copy_arr<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    out
}

/// Bọc khóa: trả về (ciphertext 1088B, shared secret 32B).
pub fn kem_encap(
    pk: &[u8; KEM_PK_LEN],
    rng: &mut impl CryptoRngCore,
) -> Result<([u8; CT_LEN], [u8; 32]), CryptoError> {
    let pk_arr = ml_kem::Encoded::<Ek>::from(*pk);
    let ek = Ek::from_bytes(&pk_arr);
    let (ct, ss): (Ct, Ss) = ek.encapsulate(rng).map_err(|_| CryptoError::Kem)?;
    Ok((copy_arr(ct.as_slice()), copy_arr(ss.as_slice())))
}

/// Mở khóa từ ciphertext.
pub fn kem_decap(sk: &DecapsKey, ct: &[u8; CT_LEN]) -> Result<[u8; 32], CryptoError> {
    let c = Ct::from(*ct);
    let ss: Ss = sk.decapsulate(&c).map_err(|_| CryptoError::Kem)?;
    Ok(copy_arr(ss.as_slice()))
}

/// Tạo cặp khóa KEM (cho NodeIdentity).
pub fn kem_generate(rng: &mut impl CryptoRngCore) -> (DecapsKey, [u8; KEM_PK_LEN]) {
    let (dk, ek) = MlKem768::generate(rng);
    let pk: [u8; KEM_PK_LEN] = copy_arr(ek.as_bytes().as_slice());
    (dk, pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn kem_roundtrip() {
        let mut rng = StdRng::seed_from_u64(9);
        let (dk, pk) = kem_generate(&mut rng);
        let (ct, ss1) = kem_encap(&pk, &mut rng).unwrap();
        let ss2 = kem_decap(&dk, &ct).unwrap();
        assert_eq!(ss1, ss2);
        assert_ne!(ss1, [0u8; 32]);
    }

    #[test]
    fn kem_ct_dung_do_dai() {
        let mut rng = StdRng::seed_from_u64(10);
        let (_, pk) = kem_generate(&mut rng);
        let (ct, _) = kem_encap(&pk, &mut rng).unwrap();
        assert_eq!(ct.len(), CT_LEN);
    }
}
