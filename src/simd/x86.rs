use crate::protocol::HASH_LEN;

pub fn trojan_password_compare(a: &[u8], b: &[u8]) -> bool {
    unsafe { simd_trojan_password_compare(a, b) }
}

#[target_feature(enable = "sse4.2")]
pub unsafe fn simd_trojan_password_compare(a: &[u8], b: &[u8]) -> bool {
    assert!(a.len() == b.len() && a.len() == HASH_LEN);

    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    let p0 = a.as_ptr();
    let p1 = b.as_ptr();

    for i in 0..3 {
        let d0 = _mm_lddqu_si128(p0.offset(i * 16) as *const _);
        let d1 = _mm_lddqu_si128(p1.offset(i * 16) as *const _);
        let eq = _mm_movemask_epi8(_mm_cmpeq_epi8(d0, d1)) as u32;
        if eq != 0xffff {
            return false;
        }
    }

    let d0 = _mm_loadu_si64(p0.offset(48) as *const _);
    let d1 = _mm_loadu_si64(p1.offset(48) as *const _);
    let eq = _mm_movemask_epi8(_mm_cmpeq_epi8(d0, d1)) as u32;
    eq == 0xffff
}
