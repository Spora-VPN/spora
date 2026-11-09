//! tcpdump packet capture inside a lab namespace — the tap feeding the Tier-1
//! QUIC fingerprint inspector ([`crate::quic_inspect`]). Spawns
//! `tcpdump -i <dev> -U -w <file> udp` as a child pinned in `ns`'s **network**
//! namespace; the child stays in the lab's mount namespace, so the pcap path
//! is shared with the suite. Returns the pcap bytes on `stop()`.
//!
//! tcpdump must be present — gate the suite with
//! `lab_main_with_tools(.., &["tcpdump"])`. Within the lab's owned netns the
//! (userns-root) process has the CAP_NET_RAW needed for AF_PACKET, same as it
//! already has CAP_NET_ADMIN for iptables.
//!
//! Stopping tcpdump does not depend on it accepting signals: where a security
//! module refuses them, the capture interface is deleted instead (see
//! [`Capture::stop`]).

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::netns::{self, Netns};

static CAP_ID: AtomicUsize = AtomicUsize::new(0);

/// How long tcpdump gets to exit after each way of stopping it. Either way
/// it exits within milliseconds; the slack is for a loaded machine.
const EXIT_GRACE: Duration = Duration::from_secs(5);

/// A running tcpdump capture. Dropping it (without `stop()`) still tears down
/// the child and removes the temp pcap, so an early scenario return can't leak.
pub struct Capture {
    child: Child,
    path: PathBuf,
    /// Where tcpdump captures, for the teardown fallback: the namespace by
    /// name (messages) and mount path (an owning `Netns` would delete it on
    /// drop), and the interface.
    ns: String,
    ns_path: String,
    dev: String,
}

impl Capture {
    /// Start capturing UDP on `dev` inside `ns`, blocking until tcpdump's
    /// capture socket is attached — it prints "listening on <dev>" on stderr
    /// once `pcap_activate` succeeds, so waiting for that line is the only
    /// race-free readiness signal (a fixed sleep loses the client's single,
    /// un-retransmitted Initial on fast veths).
    pub fn start(ns: &Netns, dev: &str) -> Result<Capture, String> {
        let id = CAP_ID.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("spora-lab-cap-{}-{id}.pcap", ns.name()));
        let _ = std::fs::remove_file(&path);
        let path_str = path.to_str().ok_or("non-utf8 temp path")?.to_string();

        let mut cmd = ns.command("tcpdump");
        // `-Z root`: don't drop privileges — the setuid to user `tcpdump`
        // fails in the lab's single-uid userns and leaves the capture empty.
        // `--immediate-mode`: deliver packets to userspace as they arrive
        // instead of after the ~1s pcap buffer timeout; without it a sub-second
        // session's packets sit in the kernel buffer and are lost on stop
        // ("received by filter" but "0 captured"). `-U`: flush each packet to
        // the savefile as written.
        cmd.args([
            "-i",
            dev,
            "--immediate-mode",
            "-U",
            "-Z",
            "root",
            "-w",
            &path_str,
            "udp",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("spawn tcpdump: {e}"))?;
        let stderr = child.stderr.take();
        // Owned from here on, so a failed start tears tcpdump down too.
        let cap = Capture {
            child,
            path,
            ns: ns.name().to_string(),
            ns_path: ns.path(),
            dev: dev.to_string(),
        };

        // Drain tcpdump's stderr on a thread, signaling once it is listening
        // (the only race-free readiness signal); draining also keeps the pipe
        // from filling.
        let stderr = stderr.ok_or("tcpdump stderr unavailable")?;
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut signaled = false;
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if !signaled && line.contains("listening on") {
                    let _ = ready_tx.send(());
                    signaled = true;
                }
            }
        });
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| format!("tcpdump never reported listening on {dev}"))?;
        std::thread::sleep(Duration::from_millis(200)); // socket-attach settle
        Ok(cap)
    }

    /// Stop tcpdump and return the pcap bytes. Normally a SIGTERM; when
    /// tcpdump cannot be signalled, the capture interface is DELETED (a veth
    /// takes its peer with it), so stop a capture only once the scenario is
    /// done with that interface. Gives up with an error, never hangs.
    pub fn stop(mut self) -> Result<Vec<u8>, String> {
        self.terminate(EXIT_GRACE)?;
        let bytes = std::fs::read(&self.path).map_err(|e| format!("read pcap: {e}"))?;
        let _ = std::fs::remove_file(&self.path);
        Ok(bytes)
    }

    /// End tcpdump and reap it, waiting at most `grace` for each way of
    /// ending it. A no-op once it has exited, so `stop()` then drop is fine.
    ///
    /// SIGTERM is not always allowed: Debian's enforcing AppArmor profile for
    /// /usr/bin/tcpdump has no `signal` rule, so kill() fails (EACCES) even
    /// from tcpdump's own uid, and tcpdump would sit in poll() on an interface
    /// gone quiet. The fallback is one the lab controls: delete the capture
    /// interface inside its namespace. libpcap then ends the capture loop
    /// ("The interface disappeared") and tcpdump exits (status 1) with every
    /// packet already in the savefile (`-U`). Taking the link down is not
    /// enough: libpcap waits for it to come back up.
    fn terminate(&mut self, grace: Duration) -> Result<(), String> {
        if self.exited_within(Duration::ZERO)? {
            return Ok(());
        }
        // Not reaped yet, so the pid is still this child's.
        let pid = self.child.id();
        let unsignalled = if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } == 0 {
            if self.exited_within(grace)? {
                return Ok(());
            }
            format!("ignored SIGTERM for {grace:?}")
        } else {
            format!("refused SIGTERM ({})", std::io::Error::last_os_error())
        };
        log::warn!(
            "tcpdump (pid {pid}) {unsignalled}; ending its capture by deleting {} in ns {}",
            self.dev,
            self.ns
        );
        let deleted = netns::run_checked(
            netns::command_at(&self.ns_path, "ip").args(["link", "del", "dev", &self.dev]),
        );
        if self.exited_within(grace)? {
            return Ok(());
        }
        let deleted = match deleted {
            Ok(_) => format!("deleting {} did not end it", self.dev),
            Err(e) => format!("deleting {} failed: {e}", self.dev),
        };
        Err(format!(
            "tcpdump (pid {pid}) capturing on {} in ns {} {unsignalled}, and {deleted}: \
             still running after {grace:?}, left behind",
            self.dev, self.ns
        ))
    }

    /// Whether tcpdump has exited (and is reaped), polling for up to `grace`.
    fn exited_within(&mut self, grace: Duration) -> Result<bool, String> {
        let deadline = Instant::now() + grace;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return Ok(true),
                Ok(None) if Instant::now() >= deadline => return Ok(false),
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => return Err(format!("wait for tcpdump: {e}")),
            }
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if let Err(e) = self.terminate(EXIT_GRACE) {
            log::error!("capture teardown: {e}");
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A `Capture` around a stand-in child, in a namespace that does not
    /// exist: the interface fallback can only fail, never touch this host.
    /// `script` prints a line once set up (e.g. its trap installed).
    fn stand_in(script: &str) -> Capture {
        let mut child = Command::new("sh")
            .args(["-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .expect("stand-in ready line");
        Capture {
            child,
            path: std::env::temp_dir().join("spora-lab-cap-unit-test-none.pcap"),
            ns: "spora-lab-no-such-ns".into(),
            ns_path: "/nonexistent/spora-lab-no-such-ns".into(),
            dev: "spora-lab-none".into(),
        }
    }

    #[test]
    fn sigterm_ends_a_capture_and_teardown_repeats_harmlessly() {
        let mut cap = stand_in("echo ready; exec sleep 30");
        let start = Instant::now();
        cap.terminate(Duration::from_secs(5)).expect("terminate");
        assert!(start.elapsed() < Duration::from_secs(5));
        // stop() then drop runs it twice: the second is a no-op.
        cap.terminate(Duration::from_secs(5))
            .expect("second terminate");
    }

    #[test]
    fn an_unstoppable_capture_is_an_error_not_a_hang() {
        // Ignores SIGTERM (SIG_IGN survives exec), and the interface fallback
        // fails: terminate must give up after its two grace periods.
        let mut cap = stand_in("trap '' TERM; echo ready; exec sleep 30");
        let grace = Duration::from_millis(200);
        let start = Instant::now();
        let err = cap.terminate(grace).expect_err("must not succeed");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "took {:?}",
            start.elapsed()
        );
        assert!(err.contains("ignored SIGTERM"), "{err}");
        assert!(err.contains("deleting spora-lab-none failed"), "{err}");
        cap.child.kill().expect("SIGKILL the stand-in");
        cap.child.wait().expect("reap the stand-in");
    }
}
