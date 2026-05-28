#![cfg(not(target_arch = "wasm32"))]

use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

const ENVOY_URL: &str = "http://localhost:10000";
const INVALIDATION_PATH: &str = "/_cextauthz/cache/invalidate";
static INTEGRATION_TEST_LOCK: Mutex<()> = Mutex::new(());

struct DockerCompose {
    dir: String,
}

impl DockerCompose {
    fn new(dir: &str) -> Self {
        let dc = Self {
            dir: dir.to_string(),
        };
        dc.run(&["up", "-d", "--build"]);
        dc
    }

    fn run(&self, args: &[&str]) {
        let output = Command::new("docker")
            .arg("compose")
            .args(args)
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("docker compose command failed");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!(
                "docker compose {:?} exited with status: {:?}\nstderr: {}",
                args, output.status, stderr
            );
        }
    }

    fn run_silent(&self, args: &[&str]) {
        if let Ok(output) = Command::new("docker")
            .arg("compose")
            .args(args)
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
        {
            if !output.status.success() {
                eprintln!(
                    "docker compose {:?} cleanup failed: {}",
                    args,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }

    fn down_silent(&self) {
        self.run_silent(&["down", "-v"]);
    }
}

impl Drop for DockerCompose {
    fn drop(&mut self) {
        self.down_silent();
    }
}

struct TestEnv {
    compose: DockerCompose,
    _guard: MutexGuard<'static, ()>,
}

fn wait_for_envoy(timeout: Duration) -> Result<(), String> {
    let client = reqwest::blocking::Client::new();
    let start = Instant::now();
    loop {
        match client.get("http://localhost:10000/").send() {
            // Envoy is ready if it responds with 200 (allowed) or 403 (denied by ext_authz).
            // Either status means the filter chain is up and running.
            Ok(resp) if resp.status().is_success() || resp.status() == 403 => return Ok(()),
            Ok(resp) => {
                eprintln!(
                    "Envoy returned non-success status: {} (retrying...)",
                    resp.status()
                );
            }
            Err(e) => {
                eprintln!("Envoy connection error: {} (retrying...)", e);
            }
        }
        if start.elapsed() > timeout {
            return Err("Envoy did not become ready in time".to_string());
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn assert_port_free(port: u16) {
    let _listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|e| {
        panic!(
            "Port {} is already in use: {}. Cannot run integration test.",
            port, e
        )
    });
    // `_listener` is dropped when the function returns, right before Docker Compose starts,
    // minimizing the race window.
}

fn stop_authz_service(compose: &DockerCompose) {
    compose.run(&["stop", "authz-service"]);
}

fn setup_compose() -> TestEnv {
    let guard = INTEGRATION_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let wasm_path = "target/wasm32-unknown-unknown/release/cextauthz.wasm";
    assert!(
        std::path::Path::new(wasm_path).exists(),
        "WASM module not found at {}. Run ./build.sh first.",
        wasm_path
    );

    assert_port_free(10000);

    let compose = DockerCompose::new("integration");
    wait_for_envoy(Duration::from_secs(30)).expect("Envoy failed to start");
    TestEnv {
        compose,
        _guard: guard,
    }
}

fn envoy_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::new()
}

fn get_root(
    client: &reqwest::blocking::Client,
    authz_value: Option<&str>,
) -> reqwest::blocking::Response {
    let mut request = client.get(format!("{ENVOY_URL}/"));
    if let Some(value) = authz_value {
        request = request.header("x-ext-authz", value);
    }
    request.send().expect("Failed to send request to Envoy")
}

fn invalidate_all(
    client: &reqwest::blocking::Client,
    secret: Option<&str>,
) -> reqwest::blocking::Response {
    let mut request = client
        .post(format!("{ENVOY_URL}{INVALIDATION_PATH}"))
        .body(r#"{"version":1,"op":"purge_all"}"#);
    if let Some(secret) = secret {
        request = request.header("x-cextauthz-invalidation-secret", secret);
    }
    request
        .send()
        .expect("Failed to send invalidation request to Envoy")
}

#[test]
fn cache_hit_survives_authz_outage_until_purge_all() {
    let env = setup_compose();
    let client = envoy_client();

    let denied = get_root(&client, None);
    assert_eq!(
        denied.status(),
        403,
        "Expected 403 Forbidden without auth header, got {}",
        denied.status()
    );

    let allowed = get_root(&client, Some("allow"));
    assert_eq!(
        allowed.status(),
        200,
        "Expected 200 OK with auth header, got {}",
        allowed.status()
    );

    stop_authz_service(&env.compose);

    let cached_allowed = get_root(&client, Some("allow"));
    assert_eq!(
        cached_allowed.status(),
        200,
        "Expected cached 200 OK after authz service stopped, got {}",
        cached_allowed.status()
    );

    let unauthorized_invalidation = invalidate_all(&client, None);
    assert_eq!(
        unauthorized_invalidation.status(),
        401,
        "Expected 401 Unauthorized without invalidation secret, got {}",
        unauthorized_invalidation.status()
    );

    let invalidated = invalidate_all(&client, Some("integration-secret"));
    assert_eq!(
        invalidated.status(),
        204,
        "Expected 204 No Content for cache invalidation, got {}",
        invalidated.status()
    );

    let after_invalidation = get_root(&client, Some("allow"));
    assert_eq!(
        after_invalidation.status(),
        503,
        "Expected 503 after cache invalidation with authz service stopped, got {}",
        after_invalidation.status()
    );

    // Note: The authz service adds x-ext-authz-check-received and
    // x-ext-authz-additional-header-override to the upstream request (not the
    // client response) via the gRPC OkResponse. nginx does not echo them back.
}

#[test]
fn invalidation_rejects_malformed_json() {
    let _env = setup_compose();
    let client = envoy_client();

    let response = client
        .post(format!("{ENVOY_URL}{INVALIDATION_PATH}"))
        .header("x-cextauthz-invalidation-secret", "integration-secret")
        .body("not-json")
        .send()
        .expect("Failed to send invalid invalidation request to Envoy");

    assert_eq!(response.status(), 400);
    assert_eq!(response.text().unwrap(), "invalid json");
}

#[test]
fn invalidation_rejects_wrong_secret() {
    let _env = setup_compose();
    let client = envoy_client();

    let response = invalidate_all(&client, Some("wrong-secret"));

    assert_eq!(response.status(), 401);
}

#[test]
fn oversized_request_body_is_rejected_before_authz_call() {
    let _env = setup_compose();
    let client = envoy_client();

    let body = "x".repeat(2048);
    let response = client
        .post(format!("{ENVOY_URL}/"))
        .header("x-ext-authz", "allow")
        .body(body)
        .send()
        .expect("Failed to send oversized request to Envoy");

    assert_eq!(response.status(), 413);
    assert_eq!(response.text().unwrap(), "Payload Too Large");
}

#[test]
fn denied_responses_are_cached() {
    let env = setup_compose();
    let client = envoy_client();

    assert_eq!(get_root(&client, None).status(), 403);

    stop_authz_service(&env.compose);

    assert_eq!(get_root(&client, None).status(), 403);
}
