use serde::Deserialize;

pub const INVALIDATION_PATH: &str = "/_cextauthz/cache/invalidate";
pub const INVALIDATION_SECRET_HEADER: &str = "x-cextauthz-invalidation-secret";
pub const MESSAGE_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationOp {
    PurgeKey,
    PurgeAll,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct InvalidationRequest {
    pub version: u32,
    pub op: InvalidationOp,
    #[serde(default)]
    pub key: Option<String>,
}

impl InvalidationRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let request: Self = serde_json::from_slice(bytes).map_err(|_| "invalid json")?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != MESSAGE_VERSION {
            return Err("unsupported version");
        }

        match self.op {
            InvalidationOp::PurgeKey => {
                let Some(key) = self.key.as_deref() else {
                    return Err("purge_key requires key");
                };
                if !key.starts_with("cache:") {
                    return Err("invalid cache key");
                }
            }
            InvalidationOp::PurgeAll => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_purge_key() {
        let request = InvalidationRequest::parse(
            br#"{"version":1,"op":"purge_key","key":"cache:0000000000000001"}"#,
        )
        .unwrap();

        assert_eq!(request.op, InvalidationOp::PurgeKey);
        assert_eq!(request.key.as_deref(), Some("cache:0000000000000001"));
    }

    #[test]
    fn rejects_purge_key_without_key() {
        let err = InvalidationRequest::parse(br#"{"version":1,"op":"purge_key"}"#).unwrap_err();
        assert_eq!(err, "purge_key requires key");
    }

    #[test]
    fn parses_purge_all() {
        let request = InvalidationRequest::parse(br#"{"version":1,"op":"purge_all"}"#).unwrap();

        assert_eq!(request.op, InvalidationOp::PurgeAll);
    }
}
