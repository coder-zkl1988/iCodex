//! 一键安装 Codex 的端到端演练：真实下载官方安装包，走完验签、解压、签名闸，装进临时目录
//! （不碰 /Applications，诊断日志也写到临时目录）。需要联网、约 700 MB 流量与 3 GB 磁盘空间，
//! 默认忽略：
//!
//! ```text
//! cargo test -p codex-plus-core --test codex_install_e2e -- --ignored --nocapture
//! ```

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore = "联网下载约 700 MB 的官方安装包"]
async fn installs_official_codex_into_a_temporary_directory() {
    use codex_plus_core::codex_install::{InstallOptions, InstallPhase, install_latest, snapshot};

    let temp = tempfile::tempdir().unwrap();
    let install_dir = temp.path().join("Applications");
    let staging_root = temp.path().join("staging");
    let log_path = temp.path().join("codex-plus.log");
    codex_plus_core::diagnostic_log::set_diagnostic_log_path_for_tests(Some(log_path.clone()));

    let outcome = install_latest(InstallOptions {
        install_dir: Some(install_dir.clone()),
        staging_root: Some(staging_root.clone()),
    })
    .await
    .unwrap_or_else(|error| panic!("安装失败：{error:#}"));
    println!("{outcome:?}");

    let app = std::path::PathBuf::from(&outcome.installed_path);
    assert_eq!(app, install_dir.join("ChatGPT.app"));
    assert!(app.join("Contents").join("MacOS").is_dir());
    // 装好的应用要能被 iCodex 自己的探测认成 Codex。
    assert_eq!(
        codex_plus_core::app_paths::find_macos_codex_app(&[install_dir.clone()]).as_deref(),
        Some(app.as_path())
    );
    let state = snapshot();
    assert_eq!(state.phase, InstallPhase::Succeeded);
    assert_eq!(state.downloaded_bytes, state.total_bytes);
    assert!(
        std::fs::read_dir(&staging_root).unwrap().next().is_none(),
        "暂存目录要清理干净"
    );
    let log = std::fs::read_to_string(&log_path).unwrap();
    for event in [
        "codex_install.start",
        "codex_install.verified",
        "codex_install.succeeded",
    ] {
        assert!(log.contains(event), "诊断日志缺少 {event}");
    }
    codex_plus_core::diagnostic_log::set_diagnostic_log_path_for_tests(None);
}
