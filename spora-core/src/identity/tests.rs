use super::*;

fn relay(host: &str, port: u16) -> RelayEndpoint {
    RelayEndpoint::new(host, port)
}

fn token(relays: Vec<RelayEndpoint>) -> Token {
    Token {
        cert_hash: [0x42u8; CERT_HASH_LEN],
        share_id: [0x17u8; SHARE_ID_LEN],
        secret: [0x99u8; SECRET_LEN],
        relays,
    }
}

fn blob_b64(version: u8) -> String {
    let mut blob = [0u8; TOKEN_BLOB_LEN];
    blob[0] = version;
    URL_SAFE_NO_PAD.encode(blob)
}

#[test]
fn token_url_round_trip() {
    let token = token(vec![relay("relay.spora.dev", 443)]);
    let url = token.to_url();
    let parsed = Token::from_url(&url).unwrap();
    assert_eq!(parsed, token);
    assert!(url.as_str().starts_with("https://spora.to/s/"));
    let blob = url.path().strip_prefix(URL_PATH_PREFIX).unwrap();
    assert_eq!(blob.len(), 60, "45 bytes, 60 base64url chars");
    assert!(
        url.as_str().ends_with("?r=relay.spora.dev:443"),
        "got {url}"
    );
}

/// A link mangled on its way to the user still carries the secret; the
/// parse error (which lands in the connection record) must not repeat it,
/// and neither may a Token formatted with `{:?}`.
#[test]
fn neither_parse_errors_nor_debug_output_carry_the_secret() {
    let token = token(vec![relay("127.0.0.1", 9)]);
    let url = token.to_url();
    let blob = url
        .path()
        .strip_prefix(URL_PATH_PREFIX)
        .unwrap()
        .to_string();
    for mangled in [
        url.as_str().replace("/s/", "/S/"),
        url.as_str().replace("/s/", "/s%2F"),
        url.as_str().replace("/s/", "//s/"),
        url.as_str().replace("/s/", "/x/"),
    ] {
        let err = Token::from_url(&Url::parse(&mangled).unwrap()).unwrap_err();
        // The blob's tail is the secret's encoding.
        assert!(!err.contains(&blob[40..]), "{mangled}: {err}");
    }

    let debug = format!("{token:?}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(!debug.contains("153"), "secret bytes (0x99) in {debug}");
}

#[test]
fn token_url_round_trips_multiple_relays() {
    let token = token(vec![
        relay("2001:db8::1", 443),
        relay("relay.spora.dev", 443),
        relay("167.71.66.250", 8443),
    ]);
    let url = token.to_url();
    let parsed = Token::from_url(&url).unwrap();
    assert_eq!(parsed, token, "order and every endpoint must round-trip");
    assert_eq!(url.query_pairs().filter(|(k, _)| k == "r").count(), 3);
}

#[test]
fn the_routing_hash_is_derived_from_cert_hash_and_share_id() {
    let t = token(vec![relay("h", 1)]);
    assert_eq!(t.routing_hash(), routing_hash(&t.cert_hash, &t.share_id));
    assert_ne!(&t.routing_hash()[..], &t.cert_hash[..]);
}

#[test]
fn shares_of_one_device_differ_in_id_secret_and_routing_hash() {
    let device = DeviceIdentity::generate();
    let a = Share::open(&device, vec![relay("h", 1)]).unwrap();
    let b = Share::open(&device, vec![relay("h", 1)]).unwrap();
    assert_eq!(a.cert_hash, b.cert_hash);
    assert_ne!(a.share_id, b.share_id);
    assert_ne!(a.secret, b.secret);
    assert_ne!(a.routing_hash(), b.routing_hash());
    assert_ne!(a.url(), b.url());
    assert!(a.secret.iter().any(|&x| x != 0));
}

#[test]
fn a_share_needs_a_relay() {
    let device = DeviceIdentity::generate();
    assert!(Share::open(&device, vec![]).is_err());
}

#[test]
fn share_blob_round_trips_every_credential_kind() {
    let device = DeviceIdentity::generate();
    let share = Share::new(
        &device,
        vec![
            RelayEntry {
                endpoint: relay("2001:db8::1", 443),
                credential: Credential::Spora,
            },
            RelayEntry {
                endpoint: RelayEndpoint::with_protocol("1.2.3.4", 8443, RelayProtocol::NoiseUdp),
                credential: Credential::Static(b"bearer".to_vec()),
            },
            RelayEntry::open(RelayEndpoint::with_protocol(
                "relay.example",
                443,
                RelayProtocol::TcpTls,
            )),
        ],
    )
    .unwrap();
    let blob = share.to_blob();
    let back = Share::from_blob(&blob).unwrap();
    assert_eq!(back, share);
    assert_eq!(
        back.url(),
        share.url(),
        "the URL is a pure function of the blob"
    );
    // The static token is in the blob, never in the URL.
    assert!(!share.url().as_str().contains("bearer"));
}

#[test]
fn share_blob_rejects_unknown_versions_garbage_and_trailing_bytes() {
    let device = DeviceIdentity::generate();
    let blob = Share::open(&device, vec![relay("h", 1)]).unwrap().to_blob();

    let mut v = blob.clone();
    v[4] = 99;
    assert!(Share::from_blob(&v).unwrap_err().contains("version"));
    let mut m = blob.clone();
    m[0] ^= 0xFF;
    assert!(Share::from_blob(&m).unwrap_err().contains("magic"));
    let mut t = blob.clone();
    t.push(0);
    assert!(Share::from_blob(&t).unwrap_err().contains("trailing"));
    for cut in [0, 10, blob.len() - 1] {
        assert!(Share::from_blob(&blob[..cut]).is_err(), "cut at {cut}");
    }
    // A huge length field is an error, never an overflow.
    let mut huge = blob[..5 + 20 + 8 + 16].to_vec();
    huge.extend_from_slice(&1u16.to_be_bytes());
    huge.extend_from_slice(&u16::MAX.to_be_bytes());
    assert!(Share::from_blob(&huge).unwrap_err().contains("truncated"));
}

#[test]
fn share_debug_hides_the_secret_and_static_tokens() {
    let device = DeviceIdentity::generate();
    let share = Share::new(
        &device,
        vec![RelayEntry {
            endpoint: relay("h", 1),
            credential: Credential::Static(b"hunter2".to_vec()),
        }],
    )
    .unwrap();
    let d = format!("{share:?}");
    assert!(d.contains("<redacted>") && !d.contains("hunter2"), "{d}");
}

#[test]
fn a_share_is_served_only_under_its_own_device() {
    let device = DeviceIdentity::generate();
    let share = Share::open(&device, vec![relay("h", 1)]).unwrap();
    let id = ShareIdentity::new(&device, &share).unwrap();
    assert_eq!(id.routing_hash, share.routing_hash());
    assert_eq!(id.cert_hash, cert_hash(&id.cert_der_bytes));
    assert_eq!(id.token(share.endpoints()), share.token());

    let other = DeviceIdentity::generate();
    let err = ShareIdentity::new(&other, &share).err().expect("refused");
    assert!(err.starts_with(IDENTITY_MISMATCH), "{err}");
}

#[test]
fn device_identity_round_trips_and_checks_its_parts() {
    let d = DeviceIdentity::generate();
    let back = DeviceIdentity::from_bytes(&d.to_bytes()).unwrap();
    assert_eq!(back.cert_hash(), d.cert_hash());
    assert_eq!(back.key_der_bytes(), d.key_der_bytes());
    let again = DeviceIdentity::from_parts(d.cert_der_bytes().to_vec(), d.key_der_bytes().to_vec())
        .unwrap();
    assert_eq!(again.cert_hash(), d.cert_hash());

    // Another device's key under this cert is refused.
    let other = DeviceIdentity::generate();
    let err =
        DeviceIdentity::from_parts(d.cert_der_bytes().to_vec(), other.key_der_bytes().to_vec())
            .unwrap_err();
    assert!(err.contains("does not belong"), "{err}");

    let mut bytes = d.to_bytes();
    bytes[0] ^= 0xFF;
    assert!(
        DeviceIdentity::from_bytes(&bytes)
            .unwrap_err()
            .contains("magic")
    );
    let mut bytes = d.to_bytes();
    bytes.extend_from_slice(b"junk");
    assert!(
        DeviceIdentity::from_bytes(&bytes)
            .unwrap_err()
            .contains("trailing")
    );
    let mut huge = DEVICE_MAGIC.to_vec();
    huge.push(DEVICE_VERSION);
    huge.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        DeviceIdentity::from_bytes(&huge)
            .unwrap_err()
            .contains("truncated")
    );
    assert!(!format!("{d:?}").contains("key_der"));
}

#[test]
fn the_device_cert_outlives_the_device() {
    // The cert is the device's for as long as the device exists: rcgen's
    // default notAfter (4096-01-01). Nothing checks it today, but a verifier
    // that someday did must not find device certs expiring.
    let d = DeviceIdentity::generate();
    let cert = CertificateDer::from(d.cert_der_bytes());
    let eec = webpki::EndEntityCert::try_from(&cert).unwrap();
    let _ = eec; // parses as an end-entity cert
    // `4096` as a GeneralizedTime appears in the DER.
    let der = d.cert_der_bytes();
    assert!(der.windows(4).any(|w| w == b"4096"), "notAfter is 4096");
}

#[test]
fn token_url_round_trips_ipv6_relay_literal() {
    let token = token(vec![relay("2001:db8::1", 443)]);
    let url = token.to_url();
    assert!(
        url.as_str().ends_with("?r=[2001:db8::1]:443"),
        "v6 literal must be bracketed, got {}",
        url
    );
    let parsed = Token::from_url(&url).unwrap();
    assert_eq!(
        parsed, token,
        "relay host must come back bare (no brackets)"
    );

    // A caller that already bracketed the literal round-trips to the
    // bare form too (no double-bracketing).
    let pre_bracketed = Token {
        relays: vec![relay("[2001:db8::1]", 443)],
        ..token.clone()
    };
    let parsed = Token::from_url(&pre_bracketed.to_url()).unwrap();
    assert_eq!(parsed.relays, vec![relay("2001:db8::1", 443)]);
}

#[test]
fn relay_endpoint_protocol_tag_round_trips() {
    // The default (UdpQuic) stays a bare host:port; a non-default protocol
    // gets a `tag/` prefix, with v6 still bracketed.
    let token = token(vec![
        RelayEndpoint::new("relay.example", 443),
        RelayEndpoint::with_protocol("1.2.3.4", 8443, RelayProtocol::Direct),
        RelayEndpoint::with_protocol("2001:db8::9", 443, RelayProtocol::Direct),
    ]);
    let url = token.to_url();
    let s = url.as_str();
    assert!(s.contains("r=relay.example:443"), "default stays bare: {s}");
    assert!(s.contains("r=direct/1.2.3.4:8443"), "direct is tagged: {s}");
    assert!(
        s.contains("r=direct/[2001:db8::9]:443"),
        "direct v6 bracketed inside the tag: {s}"
    );
    assert_eq!(
        Token::from_url(&url).unwrap(),
        token,
        "protocol must round-trip"
    );
}

#[test]
fn from_url_rejects_unknown_protocol() {
    let bad = Url::parse(&format!(
        "https://spora.to/s/{}?r=warpspeed/1.2.3.4:443",
        blob_b64(URL_VERSION)
    ))
    .unwrap();
    let err = Token::from_url(&bad).unwrap_err();
    assert!(err.contains("unknown relay protocol"), "got: {err}");
}

#[test]
fn quic_tag_parses_as_the_default_protocol() {
    let url = Url::parse(&format!(
        "https://spora.to/s/{}?r=quic/relay.example:443",
        blob_b64(URL_VERSION)
    ))
    .unwrap();
    let ep = &Token::from_url(&url).unwrap().relays[0];
    assert_eq!(ep.protocol, RelayProtocol::UdpQuic);
    assert_eq!(ep.host, "relay.example");
}

#[test]
fn from_url_rejects_unbracketed_ipv6_literal() {
    let bad = Url::parse(&format!(
        "https://spora.to/s/{}?r=2001:db8::1:443",
        blob_b64(URL_VERSION)
    ))
    .unwrap();
    let err = Token::from_url(&bad).unwrap_err();
    assert!(err.contains("bracketed"), "got: {}", err);
}

#[test]
fn from_url_rejects_malformed_bracketed_literal() {
    for r in ["[2001:db8::1]443", "[not-v6]:443", "[2001:db8::1]"] {
        let bad = Url::parse(&format!(
            "https://spora.to/s/{}?r={}",
            blob_b64(URL_VERSION),
            r
        ))
        .unwrap();
        assert!(Token::from_url(&bad).is_err(), "should reject ?r={}", r);
    }
}

#[test]
fn from_url_rejects_old_links_and_unknown_versions() {
    // A pre-share-id link: 36 bytes.
    let old = URL_SAFE_NO_PAD.encode([0u8; 36]);
    let bad = Url::parse(&format!("https://spora.to/s/{old}?r=h:1")).unwrap();
    let err = Token::from_url(&bad).unwrap_err();
    assert!(err.contains("45"), "got: {}", err);

    let bad = Url::parse(&format!("https://spora.to/s/{}?r=h:1", blob_b64(7))).unwrap();
    let err = Token::from_url(&bad).unwrap_err();
    assert!(err.contains("version"), "got: {}", err);
}

#[test]
fn from_url_rejects_missing_query() {
    let bad = Url::parse(&format!("https://spora.to/s/{}", blob_b64(URL_VERSION))).unwrap();
    let err = Token::from_url(&bad).unwrap_err();
    assert!(err.contains("?r="), "got: {}", err);
}

#[test]
fn from_url_rejects_wrong_path() {
    let bad = Url::parse(&format!(
        "https://spora.to/x/{}?r=h:1",
        blob_b64(URL_VERSION)
    ))
    .unwrap();
    let err = Token::from_url(&bad).unwrap_err();
    assert!(err.contains("/s/"), "got: {}", err);
}

#[test]
fn from_url_rejects_bad_port() {
    let bad = Url::parse(&format!(
        "https://spora.to/s/{}?r=h:notaport",
        blob_b64(URL_VERSION)
    ))
    .unwrap();
    let err = Token::from_url(&bad).unwrap_err();
    assert!(err.contains("port"), "got: {}", err);
}

#[test]
fn cert_hash_verifier_accepts_matching_and_rejects_others() {
    use rustls::client::danger::ServerCertVerifier;
    let id = ShareIdentity::generate();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verify = |expected: CertHash| {
        CertHashVerifier::new(expected, provider.clone()).verify_server_cert(
            &id.cert_der(),
            &[],
            &rustls::pki_types::ServerName::try_from("spora.peer").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        )
    };
    assert!(verify(id.cert_hash).is_ok());
    assert!(
        verify(id.routing_hash).is_err(),
        "the routing hash is not what the cert is pinned by"
    );
    assert!(verify(ShareIdentity::generate().cert_hash).is_err());
}
