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
        let _ = Command::new("docker")
            .arg("compose")
            .args(args)
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output();
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

fn wait_for_envoy(timeout: Duration) -> Result<(), String> {
    let client = reqwest::blocking::Client::new();
    let start = Instant::now();
    loop {
        match client.get("http://localhost:10000/").send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
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

#[test]
fn test_envoy_wasm_filter_proxies_request() {
    // Ensure the wasm module is built
    let wasm_path = "target/wasm32-unknown-unknown/release/cextauthz.wasm";
    assert!(
        std::path::Path::new(wasm_path).exists(),
        "WASM module not found at {}. Run ./build.sh first.",
        wasm_path
    );

    let _compose = DockerCompose::new("integration");

    wait_for_envoy(Duration::from_secs(30)).expect("Envoy failed to start");

    let response = reqwest::blocking::get("http://localhost:10000/")
        .expect("Failed to send request to Envoy");

    assert_eq!(
        response.status(),
        200,
        "Expected 200 OK, got {}",
        response.status()
    );

    // compose is dropped here, triggering docker compose down
}
