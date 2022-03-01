#![cfg_attr(docsrs, feature(doc_cfg))]

#[rustfmt::skip]
pub use chksum_arch as arch;
#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
pub use chksum_async as r#async;
#[rustfmt::skip]
pub use chksum_config as config;
#[rustfmt::skip]
pub use chksum_hash as hash;
#[cfg(feature = "sync")]
#[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
pub use chksum_sync as sync;
pub use chksum_traits::*;

pub mod prelude;
