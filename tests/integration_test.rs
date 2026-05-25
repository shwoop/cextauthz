#![cfg(not(target_arch = "wasm32"))]

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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

    fn logs(&self, service: &str) -> String {
        let output = Command::new("docker")
            .arg("compose")
            .args(["logs", "--no-color", service])
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("docker compose logs command failed");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!(
                "docker compose logs {} exited with status: {:?}\nstderr: {}",
                service, output.status, stderr
            );
        }
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}

impl Drop for DockerCompose {
    fn drop(&mut self) {
        self.down_silent();
    }
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

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn purge_all_body() -> String {
    format!(
        r#"{{"version":1,"op":"purge_all","issued_at_ms":{}}}"#,
        now_ms()
    )
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

fn allowed_authz_calls(logs: &str) -> usize {
    logs.matches("[gRPCv3][allowed]").count()
}

#[test]
fn test_ext_authz_filter() {
    let wasm_path = "target/wasm32-unknown-unknown/release/cextauthz.wasm";
    assert!(
        std::path::Path::new(wasm_path).exists(),
        "WASM module not found at {}. Run ./build.sh first.",
        wasm_path
    );

    assert_port_free(10000);
    assert_port_free(9000);
    assert_port_free(8080);

    let _compose = DockerCompose::new("integration");

    wait_for_envoy(Duration::from_secs(30)).expect("Envoy failed to start");

    let client = reqwest::blocking::Client::new();

    let unauthorized_invalidation = client
        .post("http://localhost:10000/_cextauthz/cache/invalidate")
        .body(purge_all_body())
        .send()
        .expect("Failed to send unauthorized invalidation request");

    assert_eq!(
        unauthorized_invalidation.status(),
        401,
        "Expected 401 for invalidation without shared secret, got {}",
        unauthorized_invalidation.status()
    );

    // Request without x-ext-authz header should be denied
    let denied = client
        .get("http://localhost:10000/")
        .send()
        .expect("Failed to send request to Envoy");

    assert_eq!(
        denied.status(),
        403,
        "Expected 403 Forbidden without auth header, got {}",
        denied.status()
    );

    // Request with x-ext-authz: allow header should succeed
    let allowed = client
        .get("http://localhost:10000/")
        .header("x-ext-authz", "allow")
        .send()
        .expect("Failed to send request to Envoy");

    assert_eq!(
        allowed.status(),
        200,
        "Expected 200 OK with auth header, got {}",
        allowed.status()
    );

    let authz_calls_after_first = allowed_authz_calls(&_compose.logs("authz-service"));

    // Second identical request should hit the cache and avoid another authz gRPC call.
    let allowed2 = client
        .get("http://localhost:10000/")
        .header("x-ext-authz", "allow")
        .send()
        .expect("Failed to send second request to Envoy");

    assert_eq!(
        allowed2.status(),
        200,
        "Expected 200 OK for cached request, got {}",
        allowed2.status()
    );

    let authz_calls_after_second = allowed_authz_calls(&_compose.logs("authz-service"));
    assert_eq!(
        authz_calls_after_second, authz_calls_after_first,
        "Expected second identical allowed request to be served from cache, but authz-service received another allowed gRPC call"
    );

    let invalidation = client
        .post("http://localhost:10000/_cextauthz/cache/invalidate")
        .header("x-cextauthz-invalidation-secret", "integration-secret")
        .header("content-type", "application/json")
        .body(purge_all_body())
        .send()
        .expect("Failed to send cache invalidation request");

    assert_eq!(
        invalidation.status(),
        202,
        "Expected 202 Accepted for cache invalidation, got {}",
        invalidation.status()
    );

    let allowed3 = client
        .get("http://localhost:10000/")
        .header("x-ext-authz", "allow")
        .send()
        .expect("Failed to send third request to Envoy after invalidation");

    assert_eq!(
        allowed3.status(),
        200,
        "Expected 200 OK after invalidation, got {}",
        allowed3.status()
    );

    let authz_calls_after_third = allowed_authz_calls(&_compose.logs("authz-service"));
    assert!(
        authz_calls_after_third > authz_calls_after_second,
        "Expected request after invalidation to call authz-service again; before={}, after={}",
        authz_calls_after_second,
        authz_calls_after_third
    );

    // Note: The authz service adds x-ext-authz-check-received and
    // x-ext-authz-additional-header-override to the upstream request (not the
    // client response) via the gRPC OkResponse. nginx does not echo them back.
}
