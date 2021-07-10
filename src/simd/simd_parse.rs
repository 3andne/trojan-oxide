// pub fn simd16_wrap(buf: &[u8]) -> usize {
//     unsafe { parse_simd_16(buf) }
// }

// pub fn simd8_wrap(buf: &[u8]) -> usize {
//     unsafe { parse_simd_8(buf) }
// }

// #[cfg(target_arch = "aarch64")]
// #[inline]
// #[target_feature(enable = "neon")]
// #[allow(non_snake_case, overflowing_literals)]
// unsafe fn parse_simd_16(mut buf: &[u8]) -> usize {
//     use core::arch::aarch64::*;

//     let dash_r_mask = vdupq_n_u8(0x0d);
//     let dash_n_mask = vdupq_n_u8(0x0a);

//     const BYTE_MASK_DATA_HIGH: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 32, 64, 128];
//     const BYTE_MASK_DATA_LOW: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 0, 0, 0, 0, 0, 0, 0, 0];

//     let byte_mask_high = vld1q_u8(BYTE_MASK_DATA_HIGH.as_ptr());
//     let byte_mask_low = vld1q_u8(BYTE_MASK_DATA_LOW.as_ptr());
//     let mut res = 0;
//     while buf.len() >= 16 {
//         let ptr = buf.as_ptr();
//         let data = vld1q_u8(ptr);

//         let bits1 =
//             crate::neon_move_mask!(16 vceqq_u8(dash_r_mask, data), byte_mask_high, byte_mask_low);
//         let bits2 =
//             crate::neon_move_mask!(16 vceqq_u8(dash_n_mask, data), byte_mask_high, byte_mask_low);
//         let ret = _clz_u64(_rbit_u64(((bits2 >> 1) & bits1) as u64) | 1 << 47) as usize;
//         res += ret;
//         if ret != 16 {
//             break;
//         }
//         buf = &buf[16..];
//     }
//     res
// }

// #[cfg(target_arch = "aarch64")]
// #[inline]
// #[target_feature(enable = "neon")]
// #[allow(non_snake_case, overflowing_literals)]
// unsafe fn parse_simd_8(mut buf: &[u8]) -> usize {
//     use core::arch::aarch64::*;

//     let dash_r_mask = vld1_dup_u8(&0x0d);
//     let dash_n_mask = vld1_dup_u8(&0x0a);

//     const BYTE_MASK_DATA: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
//     let byte_mask = vld1_u8(BYTE_MASK_DATA.as_ptr());
//     let mut res = 0;
//     while buf.len() >= 8 {
//         let ptr = buf.as_ptr();
//         let data = vld1_u8(ptr);
//         let bits1 = crate::neon_move_mask!(8 vceq_u8(dash_r_mask, data), byte_mask);
//         let bits2 = crate::neon_move_mask!(8 vceq_u8(dash_n_mask, data), byte_mask);

//         let ret = _clz_u64(_rbit_u64(((bits2 >> 1) & bits1) as u64) | 1 << 55) as usize;
//         res += ret;
//         if ret != 8 {
//             break;
//         }
//         buf = &buf[8..];
//     }
//     res
// }

// #[macro_export]
// macro_rules! neon_move_mask {
//     (16 $mask:expr, $filter_high:expr, $filter_low:expr) => {{
//         let masked1 = vandq_u8($mask, $filter_high);
//         let masked2 = vandq_u8($mask, $filter_low);

//         ((vaddvq_u8(masked1) as u16) << 8) + vaddvq_u8(masked2) as u16
//     }};
//     (8 $mask:expr, $filter:expr) => {{
//         let masked = vand_u8($mask, $filter);

//         vaddv_u8(masked)
//     }};
// }

// pub fn parse_scalar(buf: &[u8]) -> usize {
//     for i in 0..buf.len() - 1 {
//         if buf[i] == b'\r' && buf[i + 1] == b'\n' {
//             return i;
//         }
//     }
//     buf.len()
// }
