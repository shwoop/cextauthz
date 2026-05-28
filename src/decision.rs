#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestHeaderMutation {
    AppendIfExistsOrAdd { name: String, value: String },
    AddIfAbsent { name: String, value: String },
    OverwriteIfExistsOrAdd { name: String, value: String },
    OverwriteIfExists { name: String, value: String },
    Remove { name: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    Allow {
        request_header_mutations: Vec<RequestHeaderMutation>,
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
                request_header_mutations: allow_mutations(ok),
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

fn allow_mutations(ok: &crate::pb::OkHttpResponse) -> Vec<RequestHeaderMutation> {
    let mut mutations = Vec::with_capacity(ok.headers.len() + ok.headers_to_remove.len());

    for name in &ok.headers_to_remove {
        let normalized = name.to_ascii_lowercase();
        if is_removable_header_name(&normalized) {
            mutations.push(RequestHeaderMutation::Remove { name: normalized });
        }
    }

    mutations.extend(ok.headers.iter().filter_map(header_mutation));
    mutations
}

fn header_mutation(option: &crate::pb::HeaderValueOption) -> Option<RequestHeaderMutation> {
    let header = option.header.as_ref()?;
    if header.key.is_empty() {
        return None;
    }
    if header.value.is_empty() && !option.keep_empty_value {
        return None;
    }

    let name = header.key.to_ascii_lowercase();
    let value = header.value.clone();

    if let Some(append) = option.append.as_ref() {
        return Some(if append.value {
            RequestHeaderMutation::AppendIfExistsOrAdd { name, value }
        } else {
            RequestHeaderMutation::OverwriteIfExistsOrAdd { name, value }
        });
    }

    match std::convert::TryFrom::try_from(option.append_action)
        .unwrap_or(crate::pb::header_value_option::HeaderAppendAction::AppendIfExistsOrAdd)
    {
        crate::pb::header_value_option::HeaderAppendAction::AppendIfExistsOrAdd => {
            Some(RequestHeaderMutation::AppendIfExistsOrAdd { name, value })
        }
        crate::pb::header_value_option::HeaderAppendAction::AddIfAbsent => {
            Some(RequestHeaderMutation::AddIfAbsent { name, value })
        }
        crate::pb::header_value_option::HeaderAppendAction::OverwriteIfExistsOrAdd => {
            Some(RequestHeaderMutation::OverwriteIfExistsOrAdd { name, value })
        }
        crate::pb::header_value_option::HeaderAppendAction::OverwriteIfExists => {
            Some(RequestHeaderMutation::OverwriteIfExists { name, value })
        }
    }
}

fn is_removable_header_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with(':') && !name.eq_ignore_ascii_case("host")
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

    fn header_option(
        key: &str,
        value: &str,
        append_action: crate::pb::header_value_option::HeaderAppendAction,
    ) -> crate::pb::HeaderValueOption {
        crate::pb::HeaderValueOption {
            header: Some(crate::pb::HeaderValue {
                key: key.to_string(),
                value: value.to_string(),
            }),
            append: None,
            append_action: append_action as i32,
            keep_empty_value: false,
        }
    }

    #[test]
    fn classifies_ok_response_as_allow() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: Some(crate::pb::check_response::HttpResponse::OkResponse(
                crate::pb::OkHttpResponse {
                    headers: Vec::new(),
                    headers_to_remove: Vec::new(),
                },
            )),
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Allow {
                request_header_mutations: Vec::new()
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
                        append: None,
                        append_action:
                            crate::pb::header_value_option::HeaderAppendAction::AppendIfExistsOrAdd
                                as i32,
                        keep_empty_value: false,
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
    fn ok_response_carries_request_header_mutations_and_removals() {
        let response = crate::pb::CheckResponse {
            status: None,
            http_response: Some(crate::pb::check_response::HttpResponse::OkResponse(
                crate::pb::OkHttpResponse {
                    headers: vec![
                        header_option(
                            "x-authz-user",
                            "alice",
                            crate::pb::header_value_option::HeaderAppendAction::OverwriteIfExistsOrAdd,
                        ),
                        crate::pb::HeaderValueOption {
                            header: Some(crate::pb::HeaderValue {
                                key: "x-role".to_string(),
                                value: "".to_string(),
                            }),
                            append: None,
                            append_action: crate::pb::header_value_option::HeaderAppendAction::AddIfAbsent as i32,
                            keep_empty_value: true,
                        },
                    ],
                    headers_to_remove: vec![
                        "Authorization".to_string(),
                        ":path".to_string(),
                        "Host".to_string(),
                    ],
                },
            )),
        };

        assert_eq!(
            AuthorizationDecision::from_check_response(&response),
            AuthorizationDecision::Allow {
                request_header_mutations: vec![
                    RequestHeaderMutation::Remove {
                        name: "authorization".to_string(),
                    },
                    RequestHeaderMutation::OverwriteIfExistsOrAdd {
                        name: "x-authz-user".to_string(),
                        value: "alice".to_string(),
                    },
                    RequestHeaderMutation::AddIfAbsent {
                        name: "x-role".to_string(),
                        value: "".to_string(),
                    },
                ],
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
