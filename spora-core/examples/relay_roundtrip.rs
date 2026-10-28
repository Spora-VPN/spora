// Ad-hoc isolation test for the macOS client bring-up: does THIS machine reach
// the relay's QUIC endpoint and complete a share↔connect pairing, over the
// normal network (no NE tunnel, no sandbox)? Distinguishes a relay/network
// problem from a tunnel-plumbing bug in the appex.
//
//   cargo run -p spora-core --example relay_roundtrip
use spora_core::identity::{DeviceIdentity, RelayEndpoint, Share};
use spora_core::{Config, DEFAULT_RELAY, connect, share};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter_module("quinn", log::LevelFilter::Warn)
        .filter_module("quinn_proto", log::LevelFilter::Warn)
        .filter_module("quinn_udp", log::LevelFilter::Warn)
        .init();

    let device = DeviceIdentity::generate();
    let config = Config::default();
    // RELAY=host:port overrides the built-in relay (e.g. a local test relay).
    let relay = match std::env::var("RELAY") {
        Ok(r) => {
            let (host, port) = r.rsplit_once(':').expect("RELAY must be host:port");
            RelayEndpoint::new(host.to_string(), port.parse().expect("bad port"))
        }
        Err(_) => RelayEndpoint::new(DEFAULT_RELAY.0, DEFAULT_RELAY.1),
    };
    eprintln!("== sharing (registering with relay {:?}) ==", relay);
    let sh = Share::open(&device, vec![relay]).expect("one relay");
    let session = share(device, sh, config.clone())
        .await
        .expect("share() failed");
    eprintln!("SHARE URL: {}", session.url);

    // Let the REGISTER loop park the sharer at the relay.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    eprintln!("== connecting ==");
    match connect(session.url.clone(), &config).await {
        Ok(_) => eprintln!("RESULT: CONNECT OK — relay reachable + pairing works"),
        Err(e) => eprintln!("RESULT: CONNECT FAILED — {e}"),
    }
    std::process::exit(0);
}
