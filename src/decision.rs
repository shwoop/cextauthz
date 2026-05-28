#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    Allow {
        request_headers: Vec<(String, String)>,
    },
    Deny {
        status: u32,
        body: String,
        headers: Vec<(String, String)>,
    },
}

impl AuthorizationDecision {
    pub fn from_check_response(response: &crate::pb::CheckResponse) -> Self {
        match response.http_response.as_ref() {
            Some(crate::pb::check_response::HttpResponse::OkResponse(ok)) => Self::Allow {
                request_headers: header_pairs(&ok.headers),
            },
            Some(crate::pb::check_response::HttpResponse::DeniedResponse(denied))
            | Some(crate::pb::check_response::HttpResponse::ErrorResponse(denied)) => Self::Deny {
                status: denied
                    .status
                    .as_ref()
                    .map(|s| valid_http_status_or_forbidden(s.code))
                    .unwrap_or(403),
                body: if denied.body.is_empty() {
                    "Forbidden".to_string()
                } else {
                    denied.body.clone()
                },
                headers: header_pairs(&denied.headers),
            },
            None => Self::Deny {
                status: 403,
                body: "Forbidden".to_string(),
                headers: Vec::new(),
            },
        }
    }
}

fn valid_http_status_or_forbidden(status: i32) -> u32 {
    if (100..=599).contains(&status) {
        status as u32
    } else {
        403
    }
}

fn header_pairs(headers: &[crate::pb::HeaderValueOption]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|option| option.header.as_ref())
        .filter(|header| !header.key.is_empty())
        .map(|header| (header.key.to_ascii_lowercase(), header.value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ok_response_as_allow() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: Some(crate::pb::check_response::HttpResponse::OkResponse(
                crate::pb::OkHttpResponse {
                    headers: Vec::new(),
                },
            )),
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Allow {
                request_headers: Vec::new()
            }
        );
    }

    #[test]
    fn denied_response_carries_status_body_and_headers() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: Some(crate::pb::check_response::HttpResponse::DeniedResponse(
                crate::pb::DeniedHttpResponse {
                    status: Some(crate::pb::HttpStatus { code: 401 }),
                    headers: vec![crate::pb::HeaderValueOption {
                        header: Some(crate::pb::HeaderValue {
                            key: "www-authenticate".to_string(),
                            value: "Bearer".to_string(),
                        }),
                    }],
                    body: "missing token".to_string(),
                },
            )),
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Deny {
                status: 401,
                body: "missing token".to_string(),
                headers: vec![("www-authenticate".to_string(), "Bearer".to_string())],
            }
        );
    }

    #[test]
    fn ok_response_carries_request_header_mutations() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: Some(crate::pb::check_response::HttpResponse::OkResponse(
                crate::pb::OkHttpResponse {
                    headers: vec![crate::pb::HeaderValueOption {
                        header: Some(crate::pb::HeaderValue {
                            key: "x-authz-user".to_string(),
                            value: "alice".to_string(),
                        }),
                    }],
                },
            )),
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Allow {
                request_headers: vec![("x-authz-user".to_string(), "alice".to_string())],
            }
        );
    }

    #[test]
    fn defaults_denied_response_without_status_to_forbidden() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: Some(crate::pb::check_response::HttpResponse::DeniedResponse(
                crate::pb::DeniedHttpResponse {
                    status: None,
                    headers: Vec::new(),
                    body: String::new(),
                },
            )),
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Deny {
                status: 403,
                body: "Forbidden".to_string(),
                headers: Vec::new(),
            }
        );
    }

    #[test]
    fn defaults_invalid_denied_status_to_forbidden() {
        for status_code in [-1, 0, 99, 600] {
            let response = crate::pb::CheckResponse {
                status: None,
                http_response: Some(crate::pb::check_response::HttpResponse::DeniedResponse(
                    crate::pb::DeniedHttpResponse {
                        status: Some(crate::pb::HttpStatus { code: status_code }),
                        headers: Vec::new(),
                        body: String::new(),
                    },
                )),
            };

            assert_eq!(
                AuthorizationDecision::from_check_response(&response),
                AuthorizationDecision::Deny {
                    status: 403,
                    body: "Forbidden".to_string(),
                    headers: Vec::new(),
                }
            );
        }
    }

    #[test]
    fn defaults_missing_http_response_to_forbidden() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: None,
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Deny {
                status: 403,
                body: "Forbidden".to_string(),
                headers: Vec::new(),
            }
        );
    }

    #[test]
    fn classifies_error_response_with_status_as_deny() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: Some(crate::pb::check_response::HttpResponse::ErrorResponse(
                crate::pb::DeniedHttpResponse {
                    status: Some(crate::pb::HttpStatus { code: 503 }),
                    headers: Vec::new(),
                    body: String::new(),
                },
            )),
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Deny {
                status: 503,
                body: "Forbidden".to_string(),
                headers: Vec::new(),
            }
        );
    }
}
