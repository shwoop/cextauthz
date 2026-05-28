use std::collections::HashMap;

#[derive(Default)]
pub struct RequestParts {
    pub method: String,
    pub path: String,
    pub query: String,
    pub host: String,
    pub scheme: String,
    pub request_id: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl RequestParts {
    pub fn into_check_request(self) -> crate::pb::CheckRequest {
        crate::pb::CheckRequest {
            attributes: Some(crate::pb::AttributeContext {
                source: None,
                destination: None,
                request: Some(crate::pb::Request {
                    http: Some(crate::pb::HttpRequest {
                        id: self.request_id,
                        method: self.method,
                        headers: self.headers,
                        path: self.path,
                        host: self.host,
                        scheme: self.scheme,
                        query: self.query,
                        fragment: String::new(),
                        size: self.body.len() as i64,
                        protocol: String::new(),
                        body: String::from_utf8_lossy(&self.body).to_string(),
                        raw_body: self.body,
                    }),
                }),
                context_extensions: HashMap::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_check_request_with_raw_and_text_body() {
        let mut parts = RequestParts {
            method: "POST".to_string(),
            path: "/submit".to_string(),
            query: "a=1".to_string(),
            host: "example.com".to_string(),
            scheme: "http".to_string(),
            request_id: "request-1".to_string(),
            body: b"hello".to_vec(),
            ..Default::default()
        };
        parts
            .headers
            .insert("x-ext-authz".to_string(), "allow".to_string());

        let request = parts.into_check_request();
        let http = request.attributes.unwrap().request.unwrap().http.unwrap();

        assert_eq!(http.id, "request-1");
        assert_eq!(http.method, "POST");
        assert_eq!(http.path, "/submit");
        assert_eq!(http.query, "a=1");
        assert_eq!(http.host, "example.com");
        assert_eq!(http.scheme, "http");
        assert_eq!(http.headers.get("x-ext-authz").unwrap(), "allow");
        assert_eq!(http.size, 5);
        assert_eq!(http.body, "hello");
        assert_eq!(http.raw_body, b"hello");
    }
}
