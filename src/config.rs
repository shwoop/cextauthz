use std::time::Duration;

pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1_048_576;
pub const MAX_TIMEOUT_MS: u64 = 60_000;
pub const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CACHE_TTL_MS: u64 = 86_400_000;

#[derive(Clone, Debug, PartialEq)]
pub struct PluginSettings {
    pub timeout_ms: u64,
    pub grpc_cluster: String,
    pub max_request_body_bytes: usize,
    pub cache: crate::cache::CacheConfig,
    pub invalidation_secret: String,
}

#[derive(Debug)]
pub enum ConfigError {
    Json(serde_json::Error),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(err) => err.fmt(f),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(err) => Some(err),
            Self::Invalid(_) => None,
        }
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

#[derive(serde::Deserialize)]
struct PluginConfigJson {
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default)]
    grpc: GrpcConfigJson,
    #[serde(default)]
    request_body: RequestBodyConfigJson,
    #[serde(default)]
    cache: CacheConfigJson,
    #[serde(default)]
    invalidation: InvalidationConfigJson,
}

#[derive(Default, serde::Deserialize)]
struct GrpcConfigJson {
    #[serde(default)]
    cluster: Option<String>,
}

#[derive(serde::Deserialize)]
struct RequestBodyConfigJson {
    #[serde(default = "default_max_request_body_bytes")]
    max_bytes: usize,
}

impl Default for RequestBodyConfigJson {
    fn default() -> Self {
        Self {
            max_bytes: default_max_request_body_bytes(),
        }
    }
}

#[derive(serde::Deserialize)]
struct CacheConfigJson {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_cache_ttl_ms")]
    ttl_ms: u64,
    #[serde(default = "default_cache_max_entries")]
    max_entries: usize,
    #[serde(default)]
    headers: CacheHeadersConfigJson,
}

impl Default for CacheConfigJson {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_ms: default_cache_ttl_ms(),
            max_entries: default_cache_max_entries(),
            headers: CacheHeadersConfigJson::default(),
        }
    }
}

#[derive(serde::Deserialize)]
struct CacheHeadersConfigJson {
    #[serde(default = "default_cache_headers_mode")]
    mode: String,
    #[serde(default)]
    names: Vec<String>,
}

impl Default for CacheHeadersConfigJson {
    fn default() -> Self {
        Self {
            mode: default_cache_headers_mode(),
            names: Vec::new(),
        }
    }
}

#[derive(Default, serde::Deserialize)]
struct InvalidationConfigJson {
    #[serde(default)]
    secret: String,
}

pub fn default_timeout_ms() -> u64 {
    1000
}

fn default_max_request_body_bytes() -> usize {
    DEFAULT_MAX_REQUEST_BODY_BYTES
}

fn default_cache_ttl_ms() -> u64 {
    60_000
}

fn default_cache_max_entries() -> usize {
    1000
}

fn default_cache_headers_mode() -> String {
    "all_except_request_id".to_string()
}

impl Default for PluginSettings {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            grpc_cluster: String::new(),
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            cache: crate::cache::CacheConfig::default(),
            invalidation_secret: String::new(),
        }
    }
}

impl PluginSettings {
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let config = serde_json::from_str::<PluginConfigJson>(text)?;
        validate_timeout_ms(config.timeout_ms)?;
        let grpc_cluster =
            normalize_grpc_cluster(config.grpc.cluster.as_deref().ok_or_else(|| {
                ConfigError::Invalid("grpc.cluster must not be empty".to_string())
            })?)?;
        validate_body_limit(config.request_body.max_bytes)?;
        validate_cache(&config.cache)?;

        Ok(Self {
            timeout_ms: config.timeout_ms,
            grpc_cluster,
            max_request_body_bytes: config.request_body.max_bytes,
            cache: crate::cache::CacheConfig {
                enabled: config.cache.enabled,
                ttl: Duration::from_millis(config.cache.ttl_ms),
                max_entries: config.cache.max_entries,
                header_policy: cache_header_policy(config.cache.headers)?,
            },
            invalidation_secret: config.invalidation.secret,
        })
    }
}

fn validate_timeout_ms(timeout_ms: u64) -> Result<(), ConfigError> {
    if (1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        Ok(())
    } else {
        Err(ConfigError::Invalid(
            "timeout_ms must be between 1 and 60000".to_string(),
        ))
    }
}

fn normalize_grpc_cluster(cluster: &str) -> Result<String, ConfigError> {
    let cluster = cluster.trim();
    if cluster.is_empty() {
        Err(ConfigError::Invalid(
            "grpc.cluster must not be empty".to_string(),
        ))
    } else {
        Ok(cluster.to_string())
    }
}

fn validate_body_limit(max_bytes: usize) -> Result<(), ConfigError> {
    if (1..=MAX_REQUEST_BODY_BYTES).contains(&max_bytes) {
        Ok(())
    } else {
        Err(ConfigError::Invalid(
            "request_body.max_bytes must be between 1 and 16777216".to_string(),
        ))
    }
}

fn validate_cache(cache: &CacheConfigJson) -> Result<(), ConfigError> {
    if !cache.enabled {
        return Ok(());
    }

    if !(1..=MAX_CACHE_TTL_MS).contains(&cache.ttl_ms) {
        return Err(ConfigError::Invalid(
            "cache.ttl_ms must be between 1 and 86400000 when cache is enabled".to_string(),
        ));
    }

    if cache.max_entries == 0 {
        return Err(ConfigError::Invalid(
            "cache.max_entries must be greater than 0 when cache is enabled".to_string(),
        ));
    }

    Ok(())
}

fn cache_header_policy(
    headers: CacheHeadersConfigJson,
) -> Result<crate::cache::CacheHeaderPolicy, ConfigError> {
    let names = normalize_header_names(headers.names)?;
    match headers.mode.as_str() {
        "all_except_request_id" => Ok(crate::cache::CacheHeaderPolicy::AllExceptRequestId),
        "allowlist" => Ok(crate::cache::CacheHeaderPolicy::Allowlist(names)),
        "denylist" => Ok(crate::cache::CacheHeaderPolicy::Denylist(names)),
        _ => Err(ConfigError::Invalid(
            "cache.headers.mode must be all_except_request_id, allowlist, or denylist".to_string(),
        )),
    }
}

fn normalize_header_names(names: Vec<String>) -> Result<Vec<String>, ConfigError> {
    let mut normalized = Vec::with_capacity(names.len());
    for name in names {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(ConfigError::Invalid(
                "cache.headers.names must contain non-empty header names".to_string(),
            ));
        }
        normalized.push(name);
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_defaults_for_optional_settings() {
        let settings = PluginSettings::from_json(r#"{"grpc":{"cluster":"ext_authz"}}"#).unwrap();

        assert_eq!(settings.timeout_ms, 1000);
        assert_eq!(settings.grpc_cluster, "ext_authz");
        assert!(!settings.cache.enabled);
        assert_eq!(settings.cache.ttl, Duration::from_millis(60_000));
        assert_eq!(settings.cache.max_entries, 1000);
        assert_eq!(settings.invalidation_secret, "");
    }

    #[test]
    fn parses_cache_and_invalidation_settings() {
        let settings = PluginSettings::from_json(
            r#"{"timeout_ms":250,"grpc":{"cluster":"ext_authz"},"cache":{"enabled":true,"ttl_ms":5000,"max_entries":32},"invalidation":{"secret":"secret"}}"#,
        )
        .unwrap();

        assert_eq!(settings.timeout_ms, 250);
        assert!(settings.cache.enabled);
        assert_eq!(settings.cache.ttl, Duration::from_millis(5000));
        assert_eq!(settings.cache.max_entries, 32);
        assert_eq!(settings.invalidation_secret, "secret");
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(PluginSettings::from_json("not-json").is_err());
    }

    #[test]
    fn parses_new_operational_settings() {
        let settings = PluginSettings::from_json(
            r#"{
            "timeout_ms": 250,
            "grpc": {"cluster": "custom_ext_authz"},
            "request_body": {"max_bytes": 4096},
            "cache": {
                "enabled": true,
                "ttl_ms": 5000,
                "max_entries": 32,
                "headers": {"mode": "allowlist", "names": ["authorization", "x-ext-authz"]}
            },
            "invalidation": {"secret": "secret"}
        }"#,
        )
        .unwrap();

        assert_eq!(settings.timeout_ms, 250);
        assert_eq!(settings.grpc_cluster, "custom_ext_authz");
        assert_eq!(settings.max_request_body_bytes, 4096);
        assert!(settings.cache.enabled);
        assert_eq!(settings.cache.ttl, Duration::from_millis(5000));
        assert_eq!(settings.cache.max_entries, 32);
        assert_eq!(
            settings.cache.header_policy,
            crate::cache::CacheHeaderPolicy::Allowlist(vec![
                "authorization".to_string(),
                "x-ext-authz".to_string(),
            ])
        );
        assert_eq!(settings.invalidation_secret, "secret");
    }

    #[test]
    fn rejects_missing_grpc_cluster() {
        let err = PluginSettings::from_json("{}").unwrap_err();
        assert_eq!(err.to_string(), "grpc.cluster must not be empty");
    }

    #[test]
    fn rejects_zero_timeout() {
        let err = PluginSettings::from_json(r#"{"timeout_ms":0,"grpc":{"cluster":"ext_authz"}}"#)
            .unwrap_err();
        assert_eq!(err.to_string(), "timeout_ms must be between 1 and 60000");
    }

    #[test]
    fn rejects_empty_grpc_cluster() {
        let err = PluginSettings::from_json(r#"{"grpc":{"cluster":""}}"#).unwrap_err();
        assert_eq!(err.to_string(), "grpc.cluster must not be empty");
    }

    #[test]
    fn rejects_zero_body_limit() {
        let err = PluginSettings::from_json(
            r#"{"grpc":{"cluster":"ext_authz"},"request_body":{"max_bytes":0}}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "request_body.max_bytes must be between 1 and 16777216"
        );
    }

    #[test]
    fn rejects_enabled_cache_with_zero_ttl() {
        let err =
            PluginSettings::from_json(r#"{"grpc":{"cluster":"ext_authz"},"cache":{"enabled":true,"ttl_ms":0,"max_entries":10}}"#)
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            "cache.ttl_ms must be between 1 and 86400000 when cache is enabled"
        );
    }

    #[test]
    fn rejects_enabled_cache_with_zero_entries() {
        let err = PluginSettings::from_json(
            r#"{"grpc":{"cluster":"ext_authz"},"cache":{"enabled":true,"ttl_ms":1000,"max_entries":0}}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "cache.max_entries must be greater than 0 when cache is enabled"
        );
    }

    #[test]
    fn rejects_empty_cache_header_name() {
        let err = PluginSettings::from_json(
            r#"{"grpc":{"cluster":"ext_authz"},"cache":{"headers":{"mode":"denylist","names":[""]}}}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "cache.headers.names must contain non-empty header names"
        );
    }
}
