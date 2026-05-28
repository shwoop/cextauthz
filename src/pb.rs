use prost::Message;
use std::collections::HashMap;

#[derive(Clone, PartialEq, Message)]
pub struct CheckRequest {
    #[prost(message, optional, tag = "1")]
    pub attributes: Option<AttributeContext>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AttributeContext {
    #[prost(message, optional, tag = "1")]
    pub source: Option<Peer>,
    #[prost(message, optional, tag = "2")]
    pub destination: Option<Peer>,
    #[prost(message, optional, tag = "4")]
    pub request: Option<Request>,
    #[prost(map = "string, string", tag = "10")]
    pub context_extensions: HashMap<String, String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Peer {
    #[prost(string, tag = "2")]
    pub service: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Request {
    #[prost(message, optional, tag = "2")]
    pub http: Option<HttpRequest>,
}

#[derive(Clone, PartialEq, Message)]
pub struct HttpRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub method: String,
    #[prost(map = "string, string", tag = "3")]
    pub headers: HashMap<String, String>,
    #[prost(string, tag = "4")]
    pub path: String,
    #[prost(string, tag = "5")]
    pub host: String,
    #[prost(string, tag = "6")]
    pub scheme: String,
    #[prost(string, tag = "7")]
    pub query: String,
    #[prost(string, tag = "8")]
    pub fragment: String,
    #[prost(int64, tag = "9")]
    pub size: i64,
    #[prost(string, tag = "10")]
    pub protocol: String,
    #[prost(string, tag = "11")]
    pub body: String,
    #[prost(bytes, tag = "12")]
    pub raw_body: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct CheckResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<Status>,
    #[prost(oneof = "check_response::HttpResponse", tags = "2, 3, 5")]
    pub http_response: Option<check_response::HttpResponse>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Status {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
}

pub mod check_response {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum HttpResponse {
        #[prost(message, tag = "2")]
        DeniedResponse(super::DeniedHttpResponse),
        #[prost(message, tag = "3")]
        OkResponse(super::OkHttpResponse),
        #[prost(message, tag = "5")]
        ErrorResponse(super::DeniedHttpResponse),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct DeniedHttpResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<HttpStatus>,
    #[prost(message, repeated, tag = "2")]
    pub headers: Vec<HeaderValueOption>,
    #[prost(string, tag = "3")]
    pub body: String,
}

#[derive(Clone, PartialEq, Message)]
// TODO: model the remaining OkHttpResponse query-parameter mutation fields if Envoy starts
// exercising them in this fixture.
pub struct OkHttpResponse {
    #[prost(message, repeated, tag = "2")]
    pub headers: Vec<HeaderValueOption>,
    #[prost(string, repeated, tag = "5")]
    pub headers_to_remove: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct HttpStatus {
    #[prost(int32, tag = "1")]
    pub code: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct HeaderValueOption {
    #[prost(message, optional, tag = "1")]
    pub header: Option<HeaderValue>,
    #[prost(message, optional, tag = "2")]
    pub append: Option<BoolValue>,
    #[prost(enumeration = "header_value_option::HeaderAppendAction", tag = "3")]
    pub append_action: i32,
    #[prost(bool, tag = "4")]
    pub keep_empty_value: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct HeaderValue {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct BoolValue {
    #[prost(bool, tag = "1")]
    pub value: bool,
}

pub mod header_value_option {
    use prost::Enumeration;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
    #[repr(i32)]
    pub enum HeaderAppendAction {
        AppendIfExistsOrAdd = 0,
        AddIfAbsent = 1,
        OverwriteIfExistsOrAdd = 2,
        OverwriteIfExists = 3,
    }
}
