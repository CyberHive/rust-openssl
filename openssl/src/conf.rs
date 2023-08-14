//! Interface for processing OpenSSL configuration files.

foreign_type_and_impl_send_sync! {
    type CType = ffi::CONF;
    fn drop = ffi::NCONF_free;

    pub struct Conf;
    pub struct ConfRef;
}

#[cfg(not(boringssl))]
mod methods {
    use super::Conf;
    use crate::cvt;
    use crate::cvt_p;
    use crate::error::ErrorStack;
    use libc::c_int;
    use openssl_macros::corresponds;
    use std::ffi::CString;
    use std::path::Path;
    use std::ptr;

    pub struct ConfMethod(*mut ffi::CONF_METHOD);

    impl ConfMethod {
        /// Retrieve handle to the default OpenSSL configuration file processing function.
        #[corresponds(NCONF_default)]
        #[allow(clippy::should_implement_trait)]
        pub fn default() -> ConfMethod {
            unsafe {
                ffi::init();
                // `NCONF` stands for "New Conf", as described in crypto/conf/conf_lib.c. This is
                // a newer API than the "CONF classic" functions.
                ConfMethod(ffi::NCONF_default())
            }
        }

        /// Construct from raw pointer.
        ///
        /// # Safety
        ///
        /// The caller must ensure that the pointer is valid.
        pub unsafe fn from_ptr(ptr: *mut ffi::CONF_METHOD) -> ConfMethod {
            ConfMethod(ptr)
        }

        /// Convert to raw pointer.
        pub fn as_ptr(&self) -> *mut ffi::CONF_METHOD {
            self.0
        }
    }

    impl Conf {
        /// Create a configuration parser.
        ///
        /// # Examples
        ///
        /// ```
        /// use openssl::conf::{Conf, ConfMethod};
        ///
        /// let conf = Conf::new(ConfMethod::default());
        /// ```
        #[corresponds(NCONF_new)]
        pub fn new(method: ConfMethod) -> Result<Conf, ErrorStack> {
            unsafe { cvt_p(ffi::NCONF_new(method.as_ptr())).map(Conf) }
        }
    }

    /// configures OpenSSL using file filename and application name appname.
    /// If filename is None the standard OpenSSL configuration file is used
    /// If appname is None the standard OpenSSL application name openssl_conf is used.
    /// The behaviour can be customized using flags.
    #[corresponds(CONF_modules_load_file)]
    pub fn modules_load_file<P: AsRef<Path>>(
        filename: Option<P>,
        appname: Option<String>,
        flags: u32,
    ) -> Result<c_int, ErrorStack> {
        let filename =
            filename.map(|f| CString::new(f.as_ref().as_os_str().to_str().unwrap()).unwrap());
        let appname = appname.map(|a| CString::new(a).unwrap());

        unsafe {
            cvt(ffi::CONF_modules_load_file(
                filename.as_ref().map_or(ptr::null(), |f| f.as_ptr()),
                appname.as_ref().map_or(ptr::null(), |a| a.as_ptr()),
                flags as _,
            ))
        }
    }
}
#[cfg(not(boringssl))]
pub use methods::*;
