use quantra_netd::exec::{Exec, MockExec, missing_binary_error};
use std::os::unix::process::ExitStatusExt;

#[test]
fn missing_nft_shows_zx_tip() {
    let e = missing_binary_error("nft");
    let msg = format!("{e}");
    assert!(msg.contains("Error: 'nft' command not found"));
    assert!(msg.contains("sudo zex infuse nftables"));
    assert!(!msg.to_ascii_lowercase().contains("apt"));
}

#[tokio::test]
async fn mock_exec_scripts_calls() {
    let mock = MockExec::default();
    let out = std::process::Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: b"ok\n".to_vec(),
        stderr: Vec::new(),
    };
    mock.push("ping", &["-c", "1"], Ok(out));
    let res = mock.output("ping", &["-c", "1"]).await;
    assert!(res.is_ok());
    let calls = mock.calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "ping");
}
