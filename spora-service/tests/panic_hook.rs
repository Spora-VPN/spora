//! A panic that ends the process — one on the main thread — marks the
//! records its teardown closes as crashed, whichever thread drops them: a
//! `#[tokio::main]` runtime drops its tasks on worker threads that are not
//! themselves panicking. A test binary of its own: the panic hook and the
//! recorder's panic flag are process-wide.

use std::sync::{Arc, Mutex};

use spora_core::record::{Entry, Reason, RecordConfig, Recorder, Role};

/// Open a record, drop it unclosed on a thread that is not panicking, and
/// say how it ended.
fn unplanned_ending() -> Option<Reason> {
    let ending: Arc<Mutex<Option<Option<Reason>>>> = Arc::default();
    let seen = ending.clone();
    let cfg = RecordConfig::in_memory().with_subscriber(Arc::new(move |e: &Entry| {
        if let Entry::Close(c) = e {
            *seen.lock().unwrap() = Some(c.reason);
        }
    }));
    let rec = Recorder::start(&cfg, Role::Client, None, Vec::new(), true);
    std::thread::spawn(move || drop(rec)).join().unwrap();
    ending.lock().unwrap().expect("a dropped record closes")
}

fn panic_on_thread(name: &str) {
    let joined = std::thread::Builder::new()
        .name(name.into())
        .spawn(|| panic!("boom"))
        .unwrap()
        .join();
    assert!(joined.is_err());
}

#[test]
fn a_main_thread_panic_closes_records_as_crashed() {
    spora_service::diag::install_panic_hook();
    assert_ne!(unplanned_ending(), Some(Reason::Crashed));

    // A worker's panic is caught (by tokio, by UniFFI): the process lives
    // on, and later unplanned endings are no crash.
    panic_on_thread("tokio-runtime-worker");
    assert_ne!(unplanned_ending(), Some(Reason::Crashed));

    panic_on_thread("main");
    assert_eq!(unplanned_ending(), Some(Reason::Crashed));
}
