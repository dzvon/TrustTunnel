use trusttunnel::settings::Settings;

#[test]
fn quic_congestion_control_rejects_unknown_value() {
    let input = r#"
[listen_protocols.quic]
congestion_control = "nope"
"#;
    let parsed: Result<Settings, _> = toml::from_str(input);
    assert!(parsed.is_err());
}
