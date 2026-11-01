//! Waiting for a child process with a deadline, shared by the SSH transport and alert delivery.

use std::io::Read;
use std::process::{Child, Output};
use std::time::{Duration, Instant};

/// The most output kept from one child: far above any real scan's JSON (a few MB at most).
pub const MAX_CAPTURE: usize = 64 * 1024 * 1024;

/// Waits for `child` until `timeout`, reading whatever stdout/stderr it was given as pipes on their
/// own threads — a pipe nobody reads fills (~64 KiB) and blocks the child, which would then look
/// like a timeout. Streams that weren't piped (Windows sends ssh's to files) come back empty.
/// Returns `None` when the deadline passed; the child has then been killed and reaped.
pub fn wait_with_deadline(child: &mut Child, timeout: Duration) -> std::io::Result<Option<Output>> {
    fn drain(pipe: Option<Box<dyn Read + Send>>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let Some(mut p) = pipe else {
                return buf;
            };
            // Keep at most MAX_CAPTURE bytes but keep reading: a remote that floods output can't
            // exhaust memory here, and the child still never blocks on a full pipe.
            let mut chunk = [0u8; 64 * 1024];
            while let Ok(n) = p.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let room = MAX_CAPTURE.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..n.min(room)]);
            }
            buf
        })
    }
    let out_t = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err_t = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            // The pipes close with the process, so the readers finish.
            let _ = (out_t.join(), err_t.join());
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Ok(Some(Output {
        status,
        stdout: out_t.join().unwrap_or_default(),
        stderr: err_t.join().unwrap_or_default(),
    }))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn output_larger_than_a_pipe_is_drained_and_a_hang_is_cut_off() {
        // ~1 MiB on stdout: would block forever if nothing read the pipe.
        let mut big = Command::new("sh")
            .args(["-c", "head -c 1048576 /dev/zero"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let out = wait_with_deadline(&mut big, Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), 1_048_576);

        let mut slow = Command::new("sleep").arg("5").spawn().unwrap();
        assert!(wait_with_deadline(&mut slow, Duration::from_millis(200))
            .unwrap()
            .is_none());
    }
}
