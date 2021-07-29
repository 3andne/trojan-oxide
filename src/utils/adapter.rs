pub enum AdapterTlsPort {
    None,
    RustlsUpload,
    RustlsDownload,
}

pub struct Adapter {
    tls_config: AdapterTlsPort,
    timeout: Option<u16>,
}

impl Adapter {
    pub fn new(tls_config: AdapterTlsPort, timeout: Option<u16>) -> Self {
        Self {
            tls_config,
            timeout,
        }
    }
}
