//! 一键安装官方 Codex 桌面应用（本机还没有 Codex 时使用）。
//!
//! 安装链路参考 Codex-App-Manager（MIT，<https://github.com/Wangnov/Codex-App-Manager>）：
//! - macOS：Sparkle appcast → 下载完整包 → 用固定的 OpenAI EdDSA 公钥验签 → `ditto` 解压 →
//!   codesign / bundle id / Team ID / Gatekeeper 四道闸 → 移入应用目录。
//! - Windows：镜像清单 → 下载 MSIX → SHA-256、包身份、Authenticode 三道校验 → `Add-AppxPackage`。
//!
//! 下载源镜像优先（codexapp.agentsmirror.com，国内可达），macOS 镜像不可用时回退 OpenAI 官方源；
//! Windows 的官方渠道只有微软商店，镜像失败时由界面引导去商店安装。镜像只做字节级复制，
//! 信任锚始终是 OpenAI / 微软的签名：镜像内容被替换时验签必然失败，不会装上。
//!
//! 只负责首次安装；装好后由 Codex 自带的 Sparkle（macOS）/ 商店（Windows）负责升级。
//!
//! `macos` / `windows` 两个子模块在所有平台都参与编译、只在对应平台调用，
//! 这样任一平台的 CI 都能对另一平台的安装逻辑做类型检查。
// 共享的下载 / 校验辅助在 Windows 上只用到一部分、在 Linux 上完全不用；macOS 构建会照常报出死代码。
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

mod appcast;
mod macos;
mod sparkle;
mod windows;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

pub use windows::{STORE_DEEP_LINK, STORE_PRODUCT_ID, STORE_WEB_URL};

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const METADATA_TIMEOUT: Duration = Duration::from_secs(20);
const METADATA_MAX_BYTES: usize = 4 * 1024 * 1024;
/// 下载期间超过这么久收不到数据就判定卡死，避免界面一直停在某个百分比。
const DOWNLOAD_STALL_TIMEOUT: Duration = Duration::from_secs(60);
/// 清单没给出大小时的写盘上限，防止异常下载源无限写满磁盘。
const MAX_PACKAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const PROGRESS_PUBLISH_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum InstallPhase {
    Idle,
    Resolving,
    Downloading,
    Verifying,
    Installing,
    Succeeded,
    Failed,
    Cancelled,
}

impl InstallPhase {
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Resolving | Self::Downloading | Self::Verifying | Self::Installing
        )
    }
}

/// 安装面板轮询读取的任务快照。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallSnapshot {
    pub phase: InstallPhase,
    pub message: String,
    /// 实际使用的下载源：`mirror` / `official`。
    pub source: Option<String>,
    pub version: Option<String>,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub installed_path: Option<String>,
    pub error: Option<String>,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
}

impl Default for InstallSnapshot {
    fn default() -> Self {
        Self {
            phase: InstallPhase::Idle,
            message: String::new(),
            source: None,
            version: None,
            downloaded_bytes: 0,
            total_bytes: 0,
            installed_path: None,
            error: None,
            started_at_ms: None,
            finished_at_ms: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallOutcome {
    pub installed_path: String,
    pub version: String,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// 安装目录覆盖（仅 macOS 生效，供端到端演练用）。为空时选 `/Applications`，不可写则退到
    /// `~/Applications`，并在已能探测到 Codex 时拒绝安装；指定后跳过「已安装」检查。
    pub install_dir: Option<PathBuf>,
    /// 暂存目录根覆盖；为空时用 iCodex 状态目录下的 `codex-install/`。
    pub staging_root: Option<PathBuf>,
}

/// 下载源：镜像优先，官方兜底（Windows 只有镜像）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Mirror,
    Official,
}

impl Source {
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::Mirror => "mirror",
            Self::Official => "official",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Mirror => "镜像源",
            Self::Official => "OpenAI 官方源",
        }
    }

    pub(crate) fn resolving_message(self) -> &'static str {
        match self {
            Self::Mirror => "正在读取镜像源的最新版本…",
            Self::Official => "正在读取 OpenAI 官方源的最新版本…",
        }
    }
}

/// 换下载源也无济于事的错误（已取消、系统版本过低、目标已存在、磁盘不足……），遇到即停止回退。
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct Fatal(pub(crate) String);

pub(crate) fn fatal(message: impl Into<String>) -> anyhow::Error {
    Fatal(message.into()).into()
}

pub(crate) fn is_fatal(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Fatal>().is_some()
}

static INSTALL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static STATE: LazyLock<Mutex<InstallSnapshot>> =
    LazyLock::new(|| Mutex::new(InstallSnapshot::default()));
static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);

pub fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "linux"
    }
}

pub fn platform_supported() -> bool {
    cfg!(any(target_os = "macos", windows))
}

/// 安装面板读取的状态：任务快照 + 平台能力。只读，不会触发安装。
pub fn status() -> Value {
    let mut value = serde_json::to_value(snapshot()).unwrap_or_else(|_| json!({}));
    value["platform"] = json!(current_platform());
    value["supported"] = json!(platform_supported());
    value["storeUrl"] = if cfg!(windows) {
        json!(STORE_WEB_URL)
    } else {
        Value::Null
    };
    value
}

pub fn snapshot() -> InstallSnapshot {
    STATE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
}

/// 请求取消进行中的安装；下载循环和各阶段之间都会检查这个标记。返回当前是否有任务在进行。
pub fn cancel() -> bool {
    let active = snapshot().phase.is_active();
    if active {
        CANCEL_REQUESTED.store(true, Ordering::SeqCst);
    }
    active
}

/// 下载、校验并安装最新版官方 Codex。同一时间只允许一个安装任务。
pub async fn install_latest(options: InstallOptions) -> anyhow::Result<InstallOutcome> {
    let _guard = INSTALL_LOCK
        .try_lock()
        .map_err(|_| anyhow::anyhow!("Codex 正在安装中，请等待当前任务完成"))?;
    CANCEL_REQUESTED.store(false, Ordering::SeqCst);
    let started_at_ms = now_ms();
    publish(|state| {
        *state = InstallSnapshot {
            phase: InstallPhase::Resolving,
            message: "正在检查 Codex 安装环境…".to_string(),
            started_at_ms: Some(started_at_ms),
            ..InstallSnapshot::default()
        };
    });
    log_event(
        "codex_install.start",
        json!({
            "platform": current_platform(),
            "installDir": options.install_dir.as_ref().map(|path| path.to_string_lossy().to_string()),
        }),
    );

    let result = run_install(&options).await;
    let finished_at_ms = now_ms();
    match &result {
        Ok(outcome) => {
            publish(|state| {
                state.phase = InstallPhase::Succeeded;
                state.message = format!(
                    "Codex {} 已安装到 {}",
                    outcome.version, outcome.installed_path
                );
                state.installed_path = Some(outcome.installed_path.clone());
                state.version = Some(outcome.version.clone());
                state.source = Some(outcome.source.clone());
                state.error = None;
                state.finished_at_ms = Some(finished_at_ms);
            });
            log_event("codex_install.succeeded", json!(outcome));
        }
        Err(error) => {
            let cancelled = CANCEL_REQUESTED.load(Ordering::SeqCst);
            let detail = format!("{error:#}");
            publish(|state| {
                state.phase = if cancelled {
                    InstallPhase::Cancelled
                } else {
                    InstallPhase::Failed
                };
                state.message = if cancelled {
                    "已取消安装。".to_string()
                } else {
                    format!("安装失败：{detail}")
                };
                state.error = Some(detail.clone());
                state.finished_at_ms = Some(finished_at_ms);
            });
            log_event(
                if cancelled {
                    "codex_install.cancelled"
                } else {
                    "codex_install.failed"
                },
                json!({ "error": detail }),
            );
        }
    }
    CANCEL_REQUESTED.store(false, Ordering::SeqCst);
    result
}

#[cfg(target_os = "macos")]
async fn run_install(options: &InstallOptions) -> anyhow::Result<InstallOutcome> {
    macos::install(options).await
}

#[cfg(windows)]
async fn run_install(options: &InstallOptions) -> anyhow::Result<InstallOutcome> {
    windows::install(options).await
}

#[cfg(not(any(target_os = "macos", windows)))]
async fn run_install(_options: &InstallOptions) -> anyhow::Result<InstallOutcome> {
    bail!("当前平台暂不支持一键安装 Codex，请手动安装后在「Codex 应用路径」里选择应用目录")
}

pub(crate) fn publish(update: impl FnOnce(&mut InstallSnapshot)) {
    let mut state = STATE.lock().unwrap_or_else(|error| error.into_inner());
    update(&mut state);
}

pub(crate) fn set_phase(phase: InstallPhase, message: impl Into<String>) {
    let message = message.into();
    publish(|state| {
        state.phase = phase;
        state.message = message;
    });
}

pub(crate) fn ensure_not_cancelled() -> anyhow::Result<()> {
    if CANCEL_REQUESTED.load(Ordering::SeqCst) {
        return Err(fatal("已取消安装"));
    }
    Ok(())
}

pub(crate) fn log_event(event: &str, detail: Value) {
    // 单元测试会真实走回退、验签失败等分支，不能把演练事件写进本机 iCodex 的诊断日志。
    if cfg!(test) {
        return;
    }
    let _ = crate::diagnostic_log::append_diagnostic_log(event, detail);
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// 已能探测到 Codex 时返回它的路径：这时不应再装（避免重复安装或覆盖用户自己的安装）。
pub(crate) fn existing_codex_app() -> Option<PathBuf> {
    let settings = crate::settings::SettingsStore::default()
        .load()
        .unwrap_or_default();
    crate::app_paths::resolve_codex_app_dir_with_saved(None, Some(settings.codex_app_path.as_str()))
}

pub(crate) fn http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(format!("Codex++/{}", crate::version::VERSION))
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .build()
        .context("创建下载连接失败")
}

pub(crate) fn host_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| "未知主机".to_string())
}

/// 读取版本清单一类的小文件（appcast / manifest / checksums），带总超时与大小上限。
pub(crate) async fn fetch_text(client: &reqwest::Client, url: &str) -> anyhow::Result<String> {
    let request = async {
        let response = client.get(url).send().await?.error_for_status()?;
        if response
            .content_length()
            .is_some_and(|length| length > METADATA_MAX_BYTES as u64)
        {
            bail!("版本清单过大");
        }
        let bytes = response.bytes().await?;
        if bytes.len() > METADATA_MAX_BYTES {
            bail!("版本清单过大");
        }
        Ok::<String, anyhow::Error>(String::from_utf8(bytes.to_vec()).context("版本清单不是文本")?)
    };
    tokio::time::timeout(METADATA_TIMEOUT, request)
        .await
        .map_err(|_| anyhow::anyhow!("读取版本信息超时（{}）", host_of(url)))?
        .with_context(|| format!("读取版本信息失败（{}）", host_of(url)))
}

pub(crate) struct DownloadedFile {
    pub(crate) path: PathBuf,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

/// 流式下载到文件：边写边算 SHA-256、按节流间隔发布进度，并检查大小与取消标记。
/// 失败时留下的半截文件由调用方的暂存目录统一清理。
pub(crate) async fn download_to(
    client: &reqwest::Client,
    url: &str,
    destination: &Path,
    expected_len: Option<u64>,
) -> anyhow::Result<DownloadedFile> {
    ensure_not_cancelled()?;
    let host = host_of(url);
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("连接下载源失败（{host}）"))?
        .error_for_status()
        .with_context(|| format!("下载源返回错误（{host}）"))?;
    let declared = response.content_length();
    if let (Some(expected), Some(declared)) = (expected_len, declared)
        && expected != declared
    {
        bail!("安装包大小与清单不符（清单 {expected} 字节，下载源 {declared} 字节）");
    }
    let total = expected_len.or(declared).unwrap_or(0);
    let limit = expected_len.unwrap_or(MAX_PACKAGE_BYTES);
    publish(|state| {
        state.phase = InstallPhase::Downloading;
        state.message = format!("正在从 {host} 下载安装包…");
        state.downloaded_bytes = 0;
        state.total_bytes = total;
    });

    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("创建暂存目录失败：{}", parent.display()))?;
    }
    let file = tokio::fs::File::create(destination)
        .await
        .with_context(|| format!("无法写入暂存文件：{}", destination.display()))?;
    let mut writer = tokio::io::BufWriter::with_capacity(1 << 20, file);
    let mut digest = Sha256::new();
    let mut written = 0u64;
    let mut last_publish = Instant::now();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = tokio::time::timeout(DOWNLOAD_STALL_TIMEOUT, stream.next())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "下载超过 {} 秒没有收到数据，已中止",
                DOWNLOAD_STALL_TIMEOUT.as_secs()
            )
        })?
    {
        let chunk = chunk.with_context(|| format!("下载中断（{host}）"))?;
        ensure_not_cancelled()?;
        written = written.saturating_add(chunk.len() as u64);
        if written > limit {
            bail!("安装包超过预期大小，已中止下载");
        }
        writer
            .write_all(&chunk)
            .await
            .context("写入安装包失败（磁盘空间是否不足？）")?;
        digest.update(&chunk);
        if last_publish.elapsed() >= PROGRESS_PUBLISH_INTERVAL {
            publish(|state| state.downloaded_bytes = written);
            last_publish = Instant::now();
        }
    }
    writer.flush().await.context("写入安装包失败")?;
    writer
        .into_inner()
        .sync_all()
        .await
        .context("写入安装包失败")?;
    publish(|state| state.downloaded_bytes = written);
    if let Some(expected) = expected_len
        && written != expected
    {
        bail!("安装包不完整（应为 {expected} 字节，实际 {written} 字节）");
    }
    Ok(DownloadedFile {
        path: destination.to_path_buf(),
        bytes: written,
        sha256: format!("{:x}", digest.finalize()),
    })
}

/// 暂存目录所在卷的可用空间检查；不足时直接停止（换下载源也没用）。读不到可用空间时不拦。
pub(crate) fn ensure_free_space(dir: &Path, needed: u64) -> anyhow::Result<()> {
    let Ok(available) = fs2::available_space(dir) else {
        return Ok(());
    };
    if available < needed {
        return Err(fatal(format!(
            "磁盘可用空间不足：安装约需 {}，当前可用 {}",
            human_bytes(needed),
            human_bytes(available)
        )));
    }
    Ok(())
}

pub(crate) fn human_bytes(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    let value = bytes as f64;
    if value >= GIB {
        format!("{:.1} GB", value / GIB)
    } else {
        format!("{:.0} MB", value / MIB)
    }
}

/// 本次安装专用的暂存目录（下载的安装包、解压结果）。任务结束——成功、失败或取消——都整体删除；
/// 目录名带时间戳和进程号，只会删到自己建的那一个。
pub(crate) struct StagingDir {
    path: PathBuf,
}

impl StagingDir {
    pub(crate) fn create(options: &InstallOptions) -> anyhow::Result<Self> {
        let root = options
            .staging_root
            .clone()
            .unwrap_or_else(|| crate::paths::default_app_state_dir().join("codex-install"));
        let path = root.join(format!("{}-{}", now_ms(), std::process::id()));
        std::fs::create_dir_all(&path)
            .with_context(|| format!("创建暂存目录失败：{}", path.display()))?;
        Ok(Self { path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn download_writes_file_and_hashes_content() {
        let server = MockServer::start().await;
        let body = b"codex package bytes".to_vec();
        Mock::given(method("GET"))
            .and(path("/pkg.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("nested").join("pkg.zip");

        let downloaded = download_to(
            &http_client().unwrap(),
            &format!("{}/pkg.zip", server.uri()),
            &destination,
            Some(body.len() as u64),
        )
        .await
        .unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), body);
        assert_eq!(downloaded.bytes, body.len() as u64);
        assert_eq!(downloaded.sha256, format!("{:x}", Sha256::digest(&body)));
    }

    #[tokio::test]
    async fn download_rejects_size_that_disagrees_with_manifest() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 32]))
            .mount(&server)
            .await;
        let temp = tempfile::tempdir().unwrap();

        let error = download_to(
            &http_client().unwrap(),
            &format!("{}/pkg.zip", server.uri()),
            &temp.path().join("pkg.zip"),
            Some(16),
        )
        .await
        .err()
        .unwrap();

        assert!(format!("{error:#}").contains("大小与清单不符"), "{error:#}");
    }

    #[tokio::test]
    async fn download_surfaces_http_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let temp = tempfile::tempdir().unwrap();

        let error = download_to(
            &http_client().unwrap(),
            &format!("{}/missing.zip", server.uri()),
            &temp.path().join("pkg.zip"),
            None,
        )
        .await
        .err()
        .unwrap();

        assert!(format!("{error:#}").contains("下载源返回错误"), "{error:#}");
    }

    #[test]
    fn fatal_errors_survive_context_wrapping() {
        let error = fatal("已取消安装").context("外层");
        assert!(is_fatal(&error));
        assert!(!is_fatal(&anyhow::anyhow!("普通错误")));
    }

    #[test]
    fn status_reports_platform_capabilities() {
        let value = status();
        assert_eq!(value["platform"], json!(current_platform()));
        assert_eq!(value["supported"], json!(platform_supported()));
        assert!(value.get("phase").is_some());
        assert!(value.get("downloadedBytes").is_some());
    }

    #[test]
    fn human_bytes_uses_readable_units() {
        assert_eq!(human_bytes(512 * 1024 * 1024), "512 MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024 / 2), "1.5 GB");
    }

    #[test]
    fn staging_dir_is_removed_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let options = InstallOptions {
            staging_root: Some(temp.path().to_path_buf()),
            ..InstallOptions::default()
        };
        let staging = StagingDir::create(&options).unwrap();
        let inner = staging.path().join("payload.bin");
        std::fs::write(&inner, b"x").unwrap();
        let path = staging.path().to_path_buf();

        drop(staging);

        assert!(!path.exists());
        assert!(temp.path().exists(), "只删本次的暂存子目录，不动根目录");
    }
}
