// pub mod neon;

#[cfg(all(feature = "nightly", any(target_arch = "x86", target_arch = "x86_64")))]
pub mod x86;
#[cfg(all(feature = "nightly", any(target_arch = "x86", target_arch = "x86_64")))]
pub use x86::trojan_password_compare;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub mod fallback;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub use fallback::trojan_password_compare;
