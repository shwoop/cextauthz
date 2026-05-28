use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
pub struct PluginSettings {
    pub timeout_ms: u64,
    pub cache: crate::cache::CacheConfig,
    pub invalidation_secret: String,
}

#[derive(serde::Deserialize)]
struct PluginConfigJson {
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default)]
    cache: CacheConfigJson,
    #[serde(default)]
    invalidation: InvalidationConfigJson,
}

#[derive(serde::Deserialize)]
struct CacheConfigJson {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_cache_ttl_ms")]
    ttl_ms: u64,
    #[serde(default = "default_cache_max_entries")]
    max_entries: usize,
}

impl Default for CacheConfigJson {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_ms: default_cache_ttl_ms(),
            max_entries: default_cache_max_entries(),
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

fn default_cache_ttl_ms() -> u64 {
    60_000
}

fn default_cache_max_entries() -> usize {
    1000
}

impl Default for PluginSettings {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            cache: crate::cache::CacheConfig::default(),
            invalidation_secret: String::new(),
        }
    }
}

impl PluginSettings {
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        let config = serde_json::from_str::<PluginConfigJson>(text)?;
        Ok(Self {
            timeout_ms: config.timeout_ms,
            cache: crate::cache::CacheConfig {
                enabled: config.cache.enabled,
                ttl: Duration::from_millis(config.cache.ttl_ms),
                max_entries: config.cache.max_entries,
            },
            invalidation_secret: config.invalidation.secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_current_filter_behavior() {
        let settings = PluginSettings::from_json("{}").unwrap();

        assert_eq!(settings.timeout_ms, 1000);
        assert!(!settings.cache.enabled);
        assert_eq!(settings.cache.ttl, Duration::from_millis(60_000));
        assert_eq!(settings.cache.max_entries, 1000);
        assert_eq!(settings.invalidation_secret, "");
    }

    #[test]
    fn parses_cache_and_invalidation_settings() {
        let settings = PluginSettings::from_json(
            r#"{"timeout_ms":250,"cache":{"enabled":true,"ttl_ms":5000,"max_entries":32},"invalidation":{"secret":"secret"}}"#,
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
}
