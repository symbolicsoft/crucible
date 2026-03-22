use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HarnessError {
    #[error("failed to spawn harness process: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("harness returned invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("harness returned error: {0}")]
    HarnessError(String),
    #[error("harness process exited unexpectedly")]
    ProcessExited,
    #[error("harness function not supported: {0}")]
    Unsupported(String),
    #[error("timeout waiting for harness response")]
    Timeout,
}

/// A request sent to the harness over stdin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessRequest {
    /// The function to call (e.g., "NTT", "Compress_d", "ML_KEM_KeyGen_internal").
    pub function: String,
    /// Named inputs as hex-encoded byte arrays.
    pub inputs: HashMap<String, String>,
    /// Additional integer parameters (e.g., d for Compress_d, eta for SamplePolyCBD).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub params: HashMap<String, i64>,
}

/// A response received from the harness over stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessResponse {
    /// Named outputs as hex-encoded byte arrays.
    #[serde(default)]
    pub outputs: HashMap<String, String>,
    /// Error message if the function call failed or is unsupported.
    #[serde(default)]
    pub error: Option<String>,
    /// Whether the function is not implemented by this harness.
    #[serde(default)]
    pub unsupported: bool,
}

/// A live connection to a harness process.
pub struct Harness {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
    writer: Option<std::process::ChildStdin>,
    /// Implementation name reported by the harness.
    pub implementation: String,
    /// Functions the harness claims to support.
    pub supported_functions: Vec<String>,
}

/// The handshake response the harness sends on startup.
#[derive(Debug, Deserialize)]
struct HandshakeResponse {
    implementation: String,
    #[serde(default)]
    functions: Vec<String>,
}

impl Harness {
    /// Spawn a harness process and perform the initial handshake.
    pub fn spawn(command: &str, args: &[&str], timeout: Duration) -> Result<Self, HarnessError> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdout = child.stdout.take().expect("stdout was piped");
        let stdin = child.stdin.take().expect("stdin was piped");

        let mut reader = BufReader::new(stdout);

        // Read the handshake line.
        let mut line = String::new();
        // TODO: add timeout support via thread/poll
        let _ = timeout;
        reader.read_line(&mut line)?;

        let handshake: HandshakeResponse = serde_json::from_str(line.trim())?;

        Ok(Self {
            child,
            reader,
            writer: Some(stdin),
            implementation: handshake.implementation,
            supported_functions: handshake.functions,
        })
    }

    /// Send a request to the harness and wait for a response.
    pub fn call(&mut self, request: &HarnessRequest) -> Result<HarnessResponse, HarnessError> {
        // Check if the process is still running.
        if let Some(status) = self.child.try_wait()? {
            if !status.success() {
                return Err(HarnessError::ProcessExited);
            }
        }

        // Write request as a single JSON line.
        let writer = self.writer.as_mut().ok_or_else(|| {
            HarnessError::HarnessError("harness stdin closed".to_string())
        })?;
        let json = serde_json::to_string(request)?;
        writeln!(writer, "{json}")?;
        writer.flush()?;

        // Read one line of response.
        let mut line = String::new();
        let n = self.reader.read_line(&mut line)?;
        if n == 0 {
            return Err(HarnessError::ProcessExited);
        }

        let response: HarnessResponse = serde_json::from_str(line.trim())?;

        if response.unsupported {
            return Err(HarnessError::Unsupported(request.function.clone()));
        }

        if let Some(err) = &response.error {
            return Err(HarnessError::HarnessError(err.clone()));
        }

        Ok(response)
    }

    /// Convenience: call a function with byte-array inputs and get byte-array outputs.
    pub fn call_fn(
        &mut self,
        function: &str,
        inputs: &[(&str, &[u8])],
        params: &[(&str, i64)],
    ) -> Result<HashMap<String, Vec<u8>>, HarnessError> {
        let request = HarnessRequest {
            function: function.to_string(),
            inputs: inputs
                .iter()
                .map(|(k, v)| (k.to_string(), hex::encode(v)))
                .collect(),
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
        };

        let response = self.call(&request)?;

        let mut result = HashMap::new();
        for (key, hex_val) in &response.outputs {
            let bytes = hex::decode(hex_val).map_err(|e| {
                HarnessError::HarnessError(format!("invalid hex in output '{key}': {e}"))
            })?;
            result.insert(key.clone(), bytes);
        }

        Ok(result)
    }

    /// Shut down the harness process.
    pub fn shutdown(mut self) -> Result<(), HarnessError> {
        // Drop stdin to signal EOF.
        self.writer.take();
        self.child.wait()?;
        Ok(())
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Best-effort kill.
        let _ = self.child.kill();
    }
}
