#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    Allow,
    Deny { status: u32 },
}

impl AuthorizationDecision {
    pub fn from_check_response(response: &crate::pb::CheckResponse) -> Self {
        match response.http_response.as_ref() {
            Some(crate::pb::check_response::HttpResponse::OkResponse(_)) => Self::Allow,
            Some(crate::pb::check_response::HttpResponse::DeniedResponse(denied))
            | Some(crate::pb::check_response::HttpResponse::ErrorResponse(denied)) => Self::Deny {
                status: denied.status.as_ref().map(|s| s.code as u32).unwrap_or(403),
            },
            None => Self::Deny { status: 403 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ok_response_as_allow() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: Some(crate::pb::check_response::HttpResponse::OkResponse(
                crate::pb::OkHttpResponse {},
            )),
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Allow
        );
    }

    #[test]
    fn classifies_denied_response_with_status() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: Some(crate::pb::check_response::HttpResponse::DeniedResponse(
                crate::pb::DeniedHttpResponse {
                    status: Some(crate::pb::HttpStatus { code: 401 }),
                    body: String::new(),
                },
            )),
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Deny { status: 401 }
        );
    }

    #[test]
    fn defaults_denied_response_without_status_to_forbidden() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: Some(crate::pb::check_response::HttpResponse::DeniedResponse(
                crate::pb::DeniedHttpResponse {
                    status: None,
                    body: String::new(),
                },
            )),
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Deny { status: 403 }
        );
    }

    #[test]
    fn defaults_missing_http_response_to_forbidden() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: None,
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Deny { status: 403 }
        );
    }

    #[test]
    fn classifies_error_response_with_status_as_deny() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: Some(crate::pb::check_response::HttpResponse::ErrorResponse(
                crate::pb::DeniedHttpResponse {
                    status: Some(crate::pb::HttpStatus { code: 503 }),
                    body: String::new(),
                },
            )),
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Deny { status: 503 }
        );
    }
}
