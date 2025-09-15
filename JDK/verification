use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::net::{IpAddr, SocketAddr};
use std::fmt;
use sha2::{Sha256, Digest};
use ring::signature::{self, KeyPair, RsaKeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use ring::rand::SystemRandom;
use ring::digest;
use webpki::{EndEntityCert, TrustAnchor, Time};
use tokio::sync::RwLock as TokioRwLock;
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose};
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub enum VerificationError {
    InvalidCertificate(String),
    ExpiredCertificate,
    UntrustedRoot,
    InvalidSignature,
    MalformedData,
    NetworkError(String),
    ContentIntegrityFailure,
    PolicyViolation(String),
    CryptographicFailure,
    TimestampError,
    RevocationCheckFailed,
    OcspError(String),
    CrlError(String),
    DnsSecFailure,
    SubresourceIntegrityFailure,
    ContentSecurityPolicyViolation,
    MixedContentBlocked,
    HstsViolation,
    HpkpViolation,
    CertificateTransparencyFailure,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::InvalidCertificate(msg) => write!(f, "Invalid certificate: {}", msg),
            VerificationError::ExpiredCertificate => write!(f, "Certificate has expired"),
            VerificationError::UntrustedRoot => write!(f, "Certificate chain not trusted"),
            VerificationError::InvalidSignature => write!(f, "Invalid digital signature"),
            VerificationError::MalformedData => write!(f, "Malformed data encountered"),
            VerificationError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            VerificationError::ContentIntegrityFailure => write!(f, "Content integrity check failed"),
            VerificationError::PolicyViolation(msg) => write!(f, "Security policy violation: {}", msg),
            VerificationError::CryptographicFailure => write!(f, "Cryptographic operation failed"),
            VerificationError::TimestampError => write!(f, "Timestamp verification failed"),
            VerificationError::RevocationCheckFailed => write!(f, "Certificate revocation check failed"),
            VerificationError::OcspError(msg) => write!(f, "OCSP error: {}", msg),
            VerificationError::CrlError(msg) => write!(f, "CRL error: {}", msg),
            VerificationError::DnsSecFailure => write!(f, "DNSSEC validation failed"),
            VerificationError::SubresourceIntegrityFailure => write!(f, "Subresource integrity check failed"),
            VerificationError::ContentSecurityPolicyViolation => write!(f, "Content Security Policy violation"),
            VerificationError::MixedContentBlocked => write!(f, "Mixed content blocked"),
            VerificationError::HstsViolation => write!(f, "HTTP Strict Transport Security violation"),
            VerificationError::HpkpViolation => write!(f, "HTTP Public Key Pinning violation"),
            VerificationError::CertificateTransparencyFailure => write!(f, "Certificate Transparency validation failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: Vec<u8>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub extensions: HashMap<String, Vec<u8>>,
    pub fingerprint_sha256: [u8; 32],
    pub version: u8,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub subject_alt_names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub enforce_hsts: bool,
    pub enforce_hpkp: bool,
    pub enforce_csp: bool,
    pub block_mixed_content: bool,
    pub require_ct: bool,
    pub min_tls_version: String,
    pub allowed_cipher_suites: HashSet<String>,
    pub ocsp_stapling_required: bool,
    pub certificate_pinning: HashMap<String, Vec<[u8; 32]>>,
    pub expect_ct_policy: Option<ExpectCtPolicy>,
    pub public_key_pins: HashMap<String, Vec<[u8; 32]>>,
}

#[derive(Debug, Clone)]
pub struct ExpectCtPolicy {
    pub enforce: bool,
    pub max_age: Duration,
    pub report_uri: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OcspResponse {
    pub cert_id: Vec<u8>,
    pub cert_status: OcspCertStatus,
    pub this_update: SystemTime,
    pub next_update: Option<SystemTime>,
    pub single_extensions: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OcspCertStatus {
    Good,
    Revoked { revocation_time: SystemTime, reason: Option<u8> },
    Unknown,
}

#[derive(Debug, Clone)]
pub struct CrlEntry {
    pub serial_number: Vec<u8>,
    pub revocation_date: SystemTime,
    pub crl_reason: Option<u8>,
    pub extensions: HashMap<String, Vec<u8>>,
}

#[derive(Debug)]
pub struct TrustStore {
    pub root_certificates: Vec<TrustAnchor<'static>>,
    pub intermediate_certificates: Vec<Vec<u8>>,
    pub revoked_certificates: HashSet<Vec<u8>>,
    pub trusted_ct_logs: HashMap<Vec<u8>, Vec<u8>>,
    pub pinned_keys: HashMap<String, Vec<[u8; 32]>>,
}

#[derive(Debug)]
pub struct VerificationContext {
    pub hostname: String,
    pub port: u16,
    pub ip_address: IpAddr,
    pub certificate_chain: Vec<CertificateInfo>,
    pub ocsp_responses: Vec<OcspResponse>,
    pub sct_list: Vec<SignedCertificateTimestamp>,
    pub policy: SecurityPolicy,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone)]
pub struct SignedCertificateTimestamp {
    pub version: u8,
    pub log_id: [u8; 32],
    pub timestamp: u64,
    pub extensions: Vec<u8>,
    pub signature_algorithm: u16,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct ContentVerifier {
    pub expected_hashes: HashMap<String, Vec<u8>>,
    pub algorithms: HashSet<String>,
    pub policy_directives: HashMap<String, Vec<String>>,
    pub nonce_values: HashSet<String>,
}

#[derive(Debug)]
pub struct DnsSecValidator {
    pub trusted_keys: HashMap<String, Vec<u8>>,
    pub validation_cache: Arc<RwLock<HashMap<String, (bool, SystemTime)>>>,
}

pub struct AluminumVerificationEngine {
    trust_store: Arc<TrustStore>,
    policy_engine: Arc<TokioRwLock<PolicyEngine>>,
    crypto_provider: Arc<CryptographicProvider>,
    ocsp_client: Arc<OcspClient>,
    crl_client: Arc<CrlClient>,
    ct_validator: Arc<CertificateTransparencyValidator>,
    content_verifier: Arc<TokioRwLock<ContentVerifier>>,
    dnssec_validator: Arc<DnsSecValidator>,
    verification_cache: Arc<RwLock<HashMap<String, (bool, SystemTime)>>>,
    performance_metrics: Arc<Mutex<PerformanceMetrics>>,
}

#[derive(Debug)]
pub struct PolicyEngine {
    pub global_policy: SecurityPolicy,
    pub domain_policies: HashMap<String, SecurityPolicy>,
    pub exception_list: HashSet<String>,
    pub security_headers: HashMap<String, String>,
}

#[derive(Debug)]
pub struct CryptographicProvider {
    pub rng: SystemRandom,
    pub supported_algorithms: HashSet<String>,
    pub key_cache: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

#[derive(Debug)]
pub struct OcspClient {
    pub responder_urls: HashMap<Vec<u8>, String>,
    pub response_cache: RwLock<HashMap<Vec<u8>, (OcspResponse, SystemTime)>>,
    pub stapled_responses: RwLock<HashMap<Vec<u8>, OcspResponse>>,
}

#[derive(Debug)]
pub struct CrlClient {
    pub distribution_points: HashMap<Vec<u8>, Vec<String>>,
    pub crl_cache: RwLock<HashMap<String, (Vec<CrlEntry>, SystemTime)>>,
}

#[derive(Debug)]
pub struct CertificateTransparencyValidator {
    pub trusted_logs: HashMap<[u8; 32], Vec<u8>>,
    pub log_list_cache: RwLock<HashMap<String, SystemTime>>,
    pub sct_cache: RwLock<HashMap<Vec<u8>, Vec<SignedCertificateTimestamp>>>,
}

#[derive(Debug, Default)]
pub struct PerformanceMetrics {
    pub verification_count: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub ocsp_requests: u64,
    pub crl_downloads: u64,
    pub ct_validations: u64,
    pub average_verification_time: Duration,
}

impl AluminumVerificationEngine {
    pub fn new() -> Self {
        let trust_store = Arc::new(TrustStore {
            root_certificates: Vec::new(),
            intermediate_certificates: Vec::new(),
            revoked_certificates: HashSet::new(),
            trusted_ct_logs: HashMap::new(),
            pinned_keys: HashMap::new(),
        });

        let policy_engine = Arc::new(TokioRwLock::new(PolicyEngine {
            global_policy: SecurityPolicy::default(),
            domain_policies: HashMap::new(),
            exception_list: HashSet::new(),
            security_headers: HashMap::new(),
        }));

        let crypto_provider = Arc::new(CryptographicProvider {
            rng: SystemRandom::new(),
            supported_algorithms: HashSet::new(),
            key_cache: RwLock::new(HashMap::new()),
        });

        let ocsp_client = Arc::new(OcspClient {
            responder_urls: HashMap::new(),
            response_cache: RwLock::new(HashMap::new()),
            stapled_responses: RwLock::new(HashMap::new()),
        });

        let crl_client = Arc::new(CrlClient {
            distribution_points: HashMap::new(),
            crl_cache: RwLock::new(HashMap::new()),
        });

        let ct_validator = Arc::new(CertificateTransparencyValidator {
            trusted_logs: HashMap::new(),
            log_list_cache: RwLock::new(HashMap::new()),
            sct_cache: RwLock::new(HashMap::new()),
        });

        let content_verifier = Arc::new(TokioRwLock::new(ContentVerifier {
            expected_hashes: HashMap::new(),
            algorithms: HashSet::new(),
            policy_directives: HashMap::new(),
            nonce_values: HashSet::new(),
        }));

        let dnssec_validator = Arc::new(DnsSecValidator {
            trusted_keys: HashMap::new(),
            validation_cache: Arc::new(RwLock::new(HashMap::new())),
        });

        Self {
            trust_store,
            policy_engine,
            crypto_provider,
            ocsp_client,
            crl_client,
            ct_validator,
            content_verifier,
            dnssec_validator,
            verification_cache: Arc::new(RwLock::new(HashMap::new())),
            performance_metrics: Arc::new(Mutex::new(PerformanceMetrics::default())),
        }
    }

    pub async fn verify_complete_chain(&self, context: &VerificationContext) -> Result<bool, VerificationError> {
        let start_time = SystemTime::now();
        let cache_key = format!("{}:{}:{}", context.hostname, context.port, 
            context.certificate_chain.first().map(|c| general_purpose::STANDARD.encode(&c.fingerprint_sha256)).unwrap_or_default());

        if let Ok(cache) = self.verification_cache.read() {
            if let Some((result, timestamp)) = cache.get(&cache_key) {
                if timestamp.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(300) {
                    if let Ok(mut metrics) = self.performance_metrics.lock() {
            metrics.ct_validations += 1;
        }

        Ok(true)
    }

    async fn verify_sct_signature(&self, sct: &SignedCertificateTimestamp, cert: &CertificateInfo) -> Result<(), VerificationError> {
        if let Some(log_key) = self.ct_validator.trusted_logs.get(&sct.log_id) {
            let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, log_key);
            
            let mut signed_data = Vec::new();
            signed_data.push(sct.version);
            signed_data.extend_from_slice(&sct.log_id);
            signed_data.extend_from_slice(&sct.timestamp.to_be_bytes());
            signed_data.extend_from_slice(&cert.fingerprint_sha256);
            signed_data.extend_from_slice(&sct.extensions);

            public_key.verify(&signed_data, &sct.signature)
                .map_err(|_| VerificationError::CertificateTransparencyFailure)?;
        }

        Ok(())
    }

    async fn verify_sct_log_inclusion(&self, sct: &SignedCertificateTimestamp) -> Result<(), VerificationError> {
        if !self.ct_validator.trusted_logs.contains_key(&sct.log_id) {
            return Err(VerificationError::CertificateTransparencyFailure);
        }

        if sct.timestamp > SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() * 1000 {
            return Err(VerificationError::CertificateTransparencyFailure);
        }

        Ok(())
    }

    async fn validate_dnssec(&self, hostname: &str) -> Result<bool, VerificationError> {
        if let Ok(cache) = self.dnssec_validator.validation_cache.read() {
            if let Some((result, timestamp)) = cache.get(hostname) {
                if timestamp.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(300) {
                    return Ok(*result);
                }
            }
        }

        let validation_result = self.perform_dnssec_validation(hostname).await?;

        if let Ok(mut cache) = self.dnssec_validator.validation_cache.write() {
            cache.insert(hostname.to_string(), (validation_result, SystemTime::now()));
        }

        Ok(validation_result)
    }

    async fn perform_dnssec_validation(&self, hostname: &str) -> Result<bool, VerificationError> {
        let parts: Vec<&str> = hostname.split('.').collect();
        
        for i in 0..parts.len() {
            let domain = parts[i..].join(".");
            if let Some(trusted_key) = self.dnssec_validator.trusted_keys.get(&domain) {
                if self.verify_dnssec_chain(&domain, trusted_key).await? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn verify_dnssec_chain(&self, domain: &str, trusted_key: &[u8]) -> Result<bool, VerificationError> {
        let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, trusted_key);
        
        let zone_data = format!("{}. IN A", domain);
        let signature_data = self.fetch_dnssec_signature(domain).await?;

        public_key.verify(zone_data.as_bytes(), &signature_data)
            .map_err(|_| VerificationError::DnsSecFailure)?;

        Ok(true)
    }

    async fn fetch_dnssec_signature(&self, _domain: &str) -> Result<Vec<u8>, VerificationError> {
        Ok(vec![0u8; 256])
    }

    async fn verify_content_integrity(&self, context: &VerificationContext) -> Result<bool, VerificationError> {
        let content_verifier = self.content_verifier.read().await;
        
        self.verify_subresource_integrity(&content_verifier, context).await?;
        self.verify_content_security_policy(&content_verifier, context).await?;
        self.verify_sri_hashes(&content_verifier, context).await?;

        Ok(true)
    }

    async fn verify_subresource_integrity(&self, verifier: &ContentVerifier, _context: &VerificationContext) -> Result<(), VerificationError> {
        for (resource, expected_hash) in &verifier.expected_hashes {
            let actual_content = self.fetch_resource_content(resource).await?;
            let actual_hash = self.compute_content_hash(&actual_content, "sha256")?;
            
            if &actual_hash != expected_hash {
                return Err(VerificationE_metrics.lock() {
                        metrics.cache_hits += 1;
                    }
                    return Ok(*result);
                }
            }
        }

        if let Ok(mut metrics) = self.performance_metrics.lock() {
            metrics.cache_misses += 1;
            metrics.verification_count += 1;
        }

        let certificate_valid = self.verify_certificate_chain(context).await?;
        let revocation_valid = self.check_certificate_revocation(context).await?;
        let policy_compliant = self.enforce_security_policies(context).await?;
        let ct_valid = self.validate_certificate_transparency(context).await?;
        let dnssec_valid = self.validate_dnssec(&context.hostname).await?;
        let content_integrity_valid = self.verify_content_integrity(context).await?;

        let overall_result = certificate_valid && revocation_valid && policy_compliant && ct_valid && dnssec_valid && content_integrity_valid;

        if let Ok(mut cache) = self.verification_cache.write() {
            cache.insert(cache_key, (overall_result, SystemTime::now()));
        }

        if let Ok(mut metrics) = self.performance_metrics.lock() {
            if let Ok(elapsed) = start_time.elapsed() {
                metrics.average_verification_time = Duration::from_nanos(
                    ((metrics.average_verification_time.as_nanos() as u64 * (metrics.verification_count - 1) + elapsed.as_nanos() as u64) / metrics.verification_count) as u64
                );
            }
        }

        Ok(overall_result)
    }

    async fn verify_certificate_chain(&self, context: &VerificationContext) -> Result<bool, VerificationError> {
        if context.certificate_chain.is_empty() {
            return Err(VerificationError::InvalidCertificate("Empty certificate chain".to_string()));
        }

        for (i, cert) in context.certificate_chain.iter().enumerate() {
            self.verify_certificate_validity(cert, context.timestamp)?;
            self.verify_certificate_extensions(cert, &context.hostname)?;
            
            if i > 0 {
                self.verify_certificate_signature(&context.certificate_chain[i-1], cert)?;
            }
        }

        let root_cert = context.certificate_chain.last().unwrap();
        self.verify_trust_anchor(root_cert)?;

        self.verify_hostname_matching(&context.certificate_chain[0], &context.hostname)?;
        self.verify_key_usage(&context.certificate_chain[0])?;

        Ok(true)
    }

    fn verify_certificate_validity(&self, cert: &CertificateInfo, current_time: SystemTime) -> Result<(), VerificationError> {
        if current_time < cert.not_before {
            return Err(VerificationError::InvalidCertificate("Certificate not yet valid".to_string()));
        }
        
        if current_time > cert.not_after {
            return Err(VerificationError::ExpiredCertificate);
        }

        self.verify_certificate_structure(cert)?;
        self.verify_critical_extensions(cert)?;

        Ok(())
    }

    fn verify_certificate_structure(&self, cert: &CertificateInfo) -> Result<(), VerificationError> {
        if cert.version < 3 {
            return Err(VerificationError::InvalidCertificate("Unsupported certificate version".to_string()));
        }

        if cert.serial_number.is_empty() {
            return Err(VerificationError::InvalidCertificate("Invalid serial number".to_string()));
        }

        if cert.public_key.len() < 256 {
            return Err(VerificationError::InvalidCertificate("Public key too short".to_string()));
        }

        Ok(())
    }

    fn verify_critical_extensions(&self, cert: &CertificateInfo) -> Result<(), VerificationError> {
        for (oid, data) in &cert.extensions {
            match oid.as_str() {
                "2.5.29.15" => self.verify_key_usage_extension(data)?,
                "2.5.29.37" => self.verify_extended_key_usage_extension(data)?,
                "2.5.29.17" => self.verify_subject_alt_name_extension(data)?,
                "2.5.29.32" => self.verify_certificate_policies_extension(data)?,
                "1.3.6.1.5.5.7.1.1" => self.verify_authority_info_access_extension(data)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn verify_key_usage_extension(&self, data: &[u8]) -> Result<(), VerificationError> {
        if data.is_empty() {
            return Err(VerificationError::InvalidCertificate("Empty key usage extension".to_string()));
        }
        Ok(())
    }

    fn verify_extended_key_usage_extension(&self, data: &[u8]) -> Result<(), VerificationError> {
        if data.is_empty() {
            return Err(VerificationError::InvalidCertificate("Empty extended key usage extension".to_string()));
        }
        Ok(())
    }

    fn verify_subject_alt_name_extension(&self, data: &[u8]) -> Result<(), VerificationError> {
        if data.is_empty() {
            return Err(VerificationError::InvalidCertificate("Empty subject alternative name extension".to_string()));
        }
        Ok(())
    }

    fn verify_certificate_policies_extension(&self, data: &[u8]) -> Result<(), VerificationError> {
        if data.is_empty() {
            return Err(VerificationError::InvalidCertificate("Empty certificate policies extension".to_string()));
        }
        Ok(())
    }

    fn verify_authority_info_access_extension(&self, data: &[u8]) -> Result<(), VerificationError> {
        if data.is_empty() {
            return Err(VerificationError::InvalidCertificate("Empty authority info access extension".to_string()));
        }
        Ok(())
    }

    fn verify_certificate_extensions(&self, cert: &CertificateInfo, hostname: &str) -> Result<(), VerificationError> {
        if let Some(san_data) = cert.extensions.get("2.5.29.17") {
            self.verify_subject_alternative_names(san_data, hostname)?;
        }

        if let Some(bc_data) = cert.extensions.get("2.5.29.19") {
            self.verify_basic_constraints(bc_data)?;
        }

        if let Some(ski_data) = cert.extensions.get("2.5.29.14") {
            self.verify_subject_key_identifier(ski_data)?;
        }

        Ok(())
    }

    fn verify_subject_alternative_names(&self, data: &[u8], hostname: &str) -> Result<(), VerificationError> {
        if data.is_empty() {
            return Err(VerificationError::InvalidCertificate("Empty SAN extension".to_string()));
        }

        Ok(())
    }

    fn verify_basic_constraints(&self, data: &[u8]) -> Result<(), VerificationError> {
        if data.is_empty() {
            return Err(VerificationError::InvalidCertificate("Empty basic constraints".to_string()));
        }
        Ok(())
    }

    fn verify_subject_key_identifier(&self, data: &[u8]) -> Result<(), VerificationError> {
        if data.len() != 20 {
            return Err(VerificationError::InvalidCertificate("Invalid subject key identifier length".to_string()));
        }
        Ok(())
    }

    fn verify_certificate_signature(&self, issuer: &CertificateInfo, subject: &CertificateInfo) -> Result<(), VerificationError> {
        let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &issuer.public_key);
        
        let mut hasher = Sha256::new();
        hasher.update(&subject.public_key);
        hasher.update(&subject.subject.as_bytes());
        hasher.update(&subject.serial_number);
        let tbs_cert_hash = hasher.finalize();

        public_key.verify(&tbs_cert_hash, &subject.signature)
            .map_err(|_| VerificationError::InvalidSignature)?;

        Ok(())
    }

    fn verify_trust_anchor(&self, cert: &CertificateInfo) -> Result<(), VerificationError> {
        let cert_fingerprint = cert.fingerprint_sha256;
        
        for anchor in &self.trust_store.root_certificates {
            let mut hasher = Sha256::new();
            hasher.update(anchor.spki);
            let anchor_fingerprint = hasher.finalize();
            
            if cert_fingerprint == anchor_fingerprint.as_slice() {
                return Ok(());
            }
        }

        Err(VerificationError::UntrustedRoot)
    }

    fn verify_hostname_matching(&self, cert: &CertificateInfo, hostname: &str) -> Result<(), VerificationError> {
        if cert.subject_alt_names.iter().any(|san| self.matches_hostname(san, hostname)) {
            return Ok(());
        }

        if self.extract_common_name_from_subject(&cert.subject)
            .map(|cn| self.matches_hostname(&cn, hostname))
            .unwrap_or(false) {
            return Ok(());
        }

        Err(VerificationError::InvalidCertificate("Hostname mismatch".to_string()))
    }

    fn matches_hostname(&self, pattern: &str, hostname: &str) -> bool {
        if pattern == hostname {
            return true;
        }

        if pattern.starts_with("*.") {
            let domain = &pattern[2..];
            if let Some(dot_pos) = hostname.find('.') {
                return &hostname[dot_pos + 1..] == domain;
            }
        }

        false
    }

    fn extract_common_name_from_subject(&self, subject: &str) -> Option<String> {
        for component in subject.split(',') {
            let component = component.trim();
            if component.starts_with("CN=") {
                return Some(component[3..].to_string());
            }
        }
        None
    }

    fn verify_key_usage(&self, cert: &CertificateInfo) -> Result<(), VerificationError> {
        if !cert.key_usage.contains(&"digitalSignature".to_string()) && 
           !cert.key_usage.contains(&"keyEncipherment".to_string()) {
            return Err(VerificationError::InvalidCertificate("Invalid key usage".to_string()));
        }

        if !cert.extended_key_usage.contains(&"serverAuth".to_string()) {
            return Err(VerificationError::InvalidCertificate("Missing server authentication EKU".to_string()));
        }

        Ok(())
    }

    async fn check_certificate_revocation(&self, context: &VerificationContext) -> Result<bool, VerificationError> {
        for cert in &context.certificate_chain {
            if self.is_certificate_revoked_crl(cert).await? {
                return Err(VerificationError::RevocationCheckFailed);
            }

            if self.is_certificate_revoked_ocsp(cert, context).await? {
                return Err(VerificationError::RevocationCheckFailed);
            }
        }

        Ok(true)
    }

    async fn is_certificate_revoked_crl(&self, cert: &CertificateInfo) -> Result<bool, VerificationError> {
        if let Ok(cache) = self.crl_client.crl_cache.read() {
            for (_, (entries, _)) in cache.iter() {
                if entries.iter().any(|entry| entry.serial_number == cert.serial_number) {
                    return Ok(true);
                }
            }
        }

        if let Ok(mut metrics) = self.performance_metrics.lock() {
            metrics.crl_downloads += 1;
        }

        Ok(false)
    }

    async fn is_certificate_revoked_ocsp(&self, cert: &CertificateInfo, context: &VerificationContext) -> Result<bool, VerificationError> {
        if let Some(stapled_response) = context.ocsp_responses.iter()
            .find(|resp| self.matches_certificate(&resp.cert_id, cert)) {
            
            match &stapled_response.cert_status {
                OcspCertStatus::Revoked { .. } => return Ok(true),
                OcspCertStatus::Good => return Ok(false),
                OcspCertStatus::Unknown => {}
            }
        }

        if let Ok(cache) = self.ocsp_client.response_cache.read() {
            if let Some((response, timestamp)) = cache.get(&cert.serial_number) {
                if timestamp.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(3600) {
                    match &response.cert_status {
                        OcspCertStatus::Revoked { .. } => return Ok(true),
                        OcspCertStatus::Good => return Ok(false),
                        OcspCertStatus::Unknown => {}
                    }
                }
            }
        }

        if let Ok(mut metrics) = self.performance_metrics.lock() {
            metrics.ocsp_requests += 1;
        }

        Ok(false)
    }

    fn matches_certificate(&self, cert_id: &[u8], cert: &CertificateInfo) -> bool {
        cert_id == cert.serial_number
    }

    async fn enforce_security_policies(&self, context: &VerificationContext) -> Result<bool, VerificationError> {
        let policy_engine = self.policy_engine.read().await;
        
        let policy = policy_engine.domain_policies.get(&context.hostname)
            .unwrap_or(&policy_engine.global_policy);

        if policy.enforce_hsts {
            self.validate_hsts_policy(context)?;
        }

        if policy.enforce_hpkp {
            self.validate_hpkp_policy(context, policy)?;
        }

        if policy.enforce_csp {
            self.validate_csp_policy(context)?;
        }

        if policy.block_mixed_content {
            self.validate_mixed_content_policy(context)?;
        }

        if policy.require_ct {
            self.validate_ct_requirement(context)?;
        }

        self.validate_tls_version_policy(context, policy)?;
        self.validate_cipher_suite_policy(context, policy)?;

        Ok(true)
    }

    fn validate_hsts_policy(&self, context: &VerificationContext) -> Result<(), VerificationError> {
        if context.port != 443 {
            return Err(VerificationError::HstsViolation);
        }
        Ok(())
    }

    fn validate_hpkp_policy(&self, context: &VerificationContext, policy: &SecurityPolicy) -> Result<(), VerificationError> {
        if let Some(pinned_keys) = policy.certificate_pinning.get(&context.hostname) {
            let cert_key_hash = &context.certificate_chain[0].fingerprint_sha256;
            
            if !pinned_keys.contains(cert_key_hash) {
                return Err(VerificationError::HpkpViolation);
            }
        }
        Ok(())
    }

    fn validate_csp_policy(&self, _context: &VerificationContext) -> Result<(), VerificationError> {
        Ok(())
    }

    fn validate_mixed_content_policy(&self, context: &VerificationContext) -> Result<(), VerificationError> {
        if context.port != 443 {
            return Err(VerificationError::MixedContentBlocked);
        }
        Ok(())
    }

    fn validate_ct_requirement(&self, context: &VerificationContext) -> Result<(), VerificationError> {
        if context.sct_list.is_empty() {
            return Err(VerificationError::CertificateTransparencyFailure);
        }
        Ok(())
    }

    fn validate_tls_version_policy(&self, _context: &VerificationContext, policy: &SecurityPolicy) -> Result<(), VerificationError> {
        if policy.min_tls_version == "1.3" {
            Ok(())
        } else {
            Err(VerificationError::PolicyViolation("TLS version too low".to_string()))
        }
    }

    fn validate_cipher_suite_policy(&self, _context: &VerificationContext, _policy: &SecurityPolicy) -> Result<(), VerificationError> {
        Ok(())
    }

    async fn validate_certificate_transparency(&self, context: &VerificationContext) -> Result<bool, VerificationError> {
        if context.sct_list.is_empty() {
            return Ok(false);
        }

        for sct in &context.sct_list {
            self.verify_sct_signature(sct, &context.certificate_chain[0]).await?;
            self.verify_sct_log_inclusion(sct).await?;
        }
