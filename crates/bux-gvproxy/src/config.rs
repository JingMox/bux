//! Gvproxy configuration structures.
//!
//! [`GvproxyConfig`] is serialized to JSON and passed across the FFI
//! boundary to the Go `gvproxy_create()` function.
//!
//! **Field matrix (must stay in sync with `gvproxy-bridge/main.go`):**
//!
//! | Rust field | Go JSON tag | Notes |
//! |------------|-------------|-------|
//! | `socket_path` | `socket_path` | required |
//! | `subnet` | `subnet` | |
//! | `gateway_ip` / `gateway_mac` | same | |
//! | `guest_ip` / `guest_mac` | same | |
//! | `mtu` | `mtu` | |
//! | `port_mappings` | `port_mappings` | `{host_port, guest_port}` |
//! | `dns_zones` | `dns_zones` | |
//! | `dns_search_domains` | `dns_search_domains` | |
//! | `debug` | `debug` | |
//! | `capture_file` | `capture_file` | omit empty |
//! | `allow_net` | `allow_net` | omit empty; empty = full egress |
//! | `secrets` | `secrets` | omit empty; requires CA PEMs |
//! | `ca_cert_pem` / `ca_key_pem` | same | omit empty |

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::constants;

/// Local DNS zone served by the gateway's embedded DNS server.
///
/// Queries that don't match any zone are forwarded to the host's
/// system DNS resolver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZone {
    /// Zone name (e.g. `"myapp.local."`, `"."` for root).
    pub name: String,
    /// Default IP for unmatched queries in this zone.
    pub default_ip: String,
}

/// A single port mapping entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortMapping {
    /// Host port to bind (always `0.0.0.0` on the Go side today).
    pub host_port: u16,
    /// Guest port to forward to.
    pub guest_port: u16,
}

/// Secret placeholder substitution config for MITM (host-side only).
///
/// Wire format matches Go `SecretConfig` in `mitm_replacer.go`.
/// The real `value` is never logged: [`Debug`] redacts it.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretConfig {
    /// Logical secret name (for host bookkeeping).
    pub name: String,
    /// Hostnames (SNI / Host header) this secret applies to.
    pub hosts: Vec<String>,
    /// Placeholder string that appears in guest traffic (e.g. `<BUX_SECRET:TOKEN>`).
    pub placeholder: String,
    /// Real secret value substituted on the host proxy — never sent into the guest.
    pub value: String,
}

impl fmt::Debug for SecretConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretConfig")
            .field("name", &self.name)
            .field("hosts", &self.hosts)
            .field("placeholder", &self.placeholder)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Complete configuration for a gvproxy virtual-network instance.
///
/// All values are sent as JSON to the Go c-archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GvproxyConfig {
    /// Unix socket path for the network tap interface.
    pub socket_path: PathBuf,

    /// Virtual network subnet (e.g. `"192.168.127.0/24"`).
    pub subnet: String,

    /// Gateway IP address.
    pub gateway_ip: String,
    /// Gateway MAC address.
    pub gateway_mac: String,

    /// Guest IP address.
    pub guest_ip: String,
    /// Guest MAC address.
    pub guest_mac: String,

    /// MTU for the virtual network.
    pub mtu: u16,

    /// Port mappings.
    pub port_mappings: Vec<PortMapping>,

    /// Local DNS zones for the gateway's embedded DNS server.
    pub dns_zones: Vec<DnsZone>,

    /// DNS search domains.
    pub dns_search_domains: Vec<String>,

    /// Enable verbose logging in gvproxy.
    pub debug: bool,

    /// Optional pcap file for packet capture (debugging with Wireshark).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_file: Option<String>,

    /// Egress allow-list (hostnames / CIDRs). Empty means unrestricted egress.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_net: Vec<String>,

    /// MITM secret substitutions. Empty means no MITM.
    ///
    /// When non-empty, [`Self::ca_cert_pem`] and [`Self::ca_key_pem`] must also
    /// be set (generated via [`crate::ca::generate`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretConfig>,

    /// PEM-encoded MITM CA certificate (public). Empty when secrets unused.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ca_cert_pem: String,

    /// PEM-encoded MITM CA private key. Empty when secrets unused.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ca_key_pem: String,
}

impl GvproxyConfig {
    /// Creates a new configuration with the given socket path and port
    /// mappings, using network defaults from [`constants`].
    pub fn new(socket_path: PathBuf, port_mappings: Vec<(u16, u16)>) -> Self {
        let mut config = Self {
            socket_path,
            subnet: constants::SUBNET.to_owned(),
            gateway_ip: constants::GATEWAY_IP.to_owned(),
            gateway_mac: constants::GATEWAY_MAC_STRING.to_owned(),
            guest_ip: constants::GUEST_IP.to_owned(),
            guest_mac: constants::GUEST_MAC_STRING.to_owned(),
            mtu: constants::DEFAULT_MTU,
            port_mappings: port_mappings
                .into_iter()
                .map(|(host_port, guest_port)| PortMapping {
                    host_port,
                    guest_port,
                })
                .collect(),
            dns_zones: Vec::new(),
            dns_search_domains: constants::DNS_SEARCH_DOMAINS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            debug: false,
            capture_file: None,
            allow_net: Vec::new(),
            secrets: Vec::new(),
            ca_cert_pem: String::new(),
            ca_key_pem: String::new(),
        };

        // Allow packet capture via environment variable.
        if let Ok(path) = std::env::var("BUX_GVPROXY_CAPTURE_FILE") {
            if !path.is_empty() {
                tracing::info!(
                    path,
                    "enabling packet capture from BUX_GVPROXY_CAPTURE_FILE"
                );
                config.capture_file = Some(path);
                config.debug = true;
            }
        }

        config
    }

    /// Enable verbose debug logging.
    #[must_use]
    pub const fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Set custom DNS zones.
    #[must_use]
    pub fn with_dns_zones(mut self, zones: Vec<DnsZone>) -> Self {
        self.dns_zones = zones;
        self
    }

    /// Set custom MTU.
    #[must_use]
    pub const fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Enable packet capture to a pcap file.
    #[must_use]
    pub fn with_capture_file(mut self, path: String) -> Self {
        self.capture_file = Some(path);
        self
    }

    /// Set egress allow-list rules. Empty = unrestricted egress.
    #[must_use]
    pub fn with_allow_net(mut self, allow_net: Vec<String>) -> Self {
        self.allow_net = allow_net;
        self
    }

    /// Attach MITM secrets and CA PEMs.
    ///
    /// Callers must supply a CA (see [`crate::ca::generate`]) whenever
    /// `secrets` is non-empty; the Go side loads CA only when secrets exist.
    #[must_use]
    pub fn with_secrets(
        mut self,
        secrets: Vec<SecretConfig>,
        ca_cert_pem: String,
        ca_key_pem: String,
    ) -> Self {
        self.secrets = secrets;
        self.ca_cert_pem = ca_cert_pem;
        self.ca_key_pem = ca_key_pem;
        self
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items,
    reason = "tests may unwrap and index; not production paths"
)]
mod tests {
    use super::*;
    use crate::ca;

    fn test_socket() -> PathBuf {
        PathBuf::from("/tmp/test-gvproxy.sock")
    }

    #[test]
    fn defaults() {
        let cfg = GvproxyConfig::new(test_socket(), vec![]);
        assert_eq!(cfg.subnet, "192.168.127.0/24");
        assert_eq!(cfg.gateway_ip, "192.168.127.1");
        assert_eq!(cfg.guest_ip, "192.168.127.2");
        assert_eq!(cfg.mtu, 1500);
        assert!(!cfg.debug);
        assert!(cfg.allow_net.is_empty());
        assert!(cfg.secrets.is_empty());
        assert!(cfg.ca_cert_pem.is_empty());
        assert!(cfg.ca_key_pem.is_empty());
    }

    #[test]
    fn port_mappings() {
        let cfg = GvproxyConfig::new(test_socket(), vec![(8080, 80), (8443, 443)]);
        assert_eq!(cfg.port_mappings.len(), 2);
        assert_eq!(cfg.port_mappings[0].host_port, 8080);
        assert_eq!(cfg.port_mappings[0].guest_port, 80);
    }

    #[test]
    fn builder_pattern() {
        let cfg = GvproxyConfig::new(test_socket(), vec![(8080, 80)])
            .with_debug(true)
            .with_mtu(9000)
            .with_allow_net(vec!["example.com".into()]);
        assert!(cfg.debug);
        assert_eq!(cfg.mtu, 9000);
        assert_eq!(cfg.allow_net, vec!["example.com".to_owned()]);
    }

    #[test]
    fn serde_roundtrip() {
        let cfg = GvproxyConfig::new(test_socket(), vec![(8080, 80)]);
        let json = serde_json::to_string(&cfg).unwrap();
        let de: GvproxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg.subnet, de.subnet);
        assert_eq!(cfg.socket_path, de.socket_path);
    }

    #[test]
    fn empty_allow_net_and_secrets_omitted_from_json() {
        let cfg = GvproxyConfig::new(test_socket(), vec![]);
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(
            !json.contains("allow_net"),
            "empty allow_net must omit: {json}"
        );
        assert!(!json.contains("secrets"), "empty secrets must omit: {json}");
        assert!(
            !json.contains("ca_cert_pem"),
            "empty ca_cert_pem must omit: {json}"
        );
        assert!(
            !json.contains("ca_key_pem"),
            "empty ca_key_pem must omit: {json}"
        );
    }

    #[test]
    fn allow_net_and_secrets_json_parity_with_go() {
        let ca = ca::generate().unwrap();
        let cfg = GvproxyConfig::new(test_socket(), vec![(8080, 80)])
            .with_allow_net(vec!["api.example.com".into(), "10.0.0.0/8".into()])
            .with_secrets(
                vec![SecretConfig {
                    name: "TOKEN".into(),
                    hosts: vec!["api.example.com".into()],
                    placeholder: "<BUX_SECRET:TOKEN>".into(),
                    value: "super-secret".into(),
                }],
                ca.cert_pem.clone(),
                ca.key_pem.clone(),
            );

        let json = serde_json::to_string(&cfg).unwrap();
        // Go tags (main.go / mitm_replacer.go)
        assert!(json.contains("\"allow_net\""));
        assert!(json.contains("api.example.com"));
        assert!(json.contains("\"secrets\""));
        assert!(json.contains("\"placeholder\""));
        assert!(json.contains("<BUX_SECRET:TOKEN>"));
        assert!(json.contains("\"ca_cert_pem\""));
        assert!(json.contains("\"ca_key_pem\""));
        assert!(json.contains("BEGIN CERTIFICATE"));
        assert!(json.contains("BEGIN PRIVATE KEY") || json.contains("BEGIN EC PRIVATE KEY"));

        let de: GvproxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(de.allow_net.len(), 2);
        assert_eq!(de.secrets.len(), 1);
        assert_eq!(de.secrets[0].value, "super-secret");
        assert_eq!(de.ca_cert_pem, ca.cert_pem);
        assert_eq!(de.ca_key_pem, ca.key_pem);
    }

    #[test]
    fn secret_debug_redacts_value() {
        let s = SecretConfig {
            name: "TOKEN".into(),
            hosts: vec!["h".into()],
            placeholder: "p".into(),
            value: "must-not-appear".into(),
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("must-not-appear"));
    }

    #[test]
    fn socket_path_in_json() {
        let cfg = GvproxyConfig::new(
            PathBuf::from("/data/bux/socks/vm-abc.sock"),
            vec![(8080, 80)],
        );
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("socket_path"));
        assert!(json.contains("/data/bux/socks/vm-abc.sock"));
    }

    #[test]
    fn different_sockets_produce_different_json() {
        let a = GvproxyConfig::new(PathBuf::from("/a/net.sock"), vec![(8080, 80)]);
        let b = GvproxyConfig::new(PathBuf::from("/b/net.sock"), vec![(8080, 80)]);
        assert_ne!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }
}
