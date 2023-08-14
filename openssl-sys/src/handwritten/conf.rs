use super::super::*;

extern "C" {
    pub fn NCONF_new(meth: *mut CONF_METHOD) -> *mut CONF;
    pub fn NCONF_default() -> *mut CONF_METHOD;
    pub fn NCONF_free(conf: *mut CONF);
    pub fn CONF_modules_load_file(
        filename: *const c_char,
        appname: *const c_char,
        flags: c_ulong,
    ) -> c_int;
}
