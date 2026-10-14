//! macOS 安装：Sparkle 完整包 → OpenAI 验签 → `ditto` 解压 → 四道签名闸 → 移入应用目录。
//!
//! 所有平台都参与编译（便于任一平台的 CI 做类型检查），只在 macOS 上调用。
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, bail};
use serde_json::json;

use super::appcast::{self, AppcastItem};
use super::sparkle::{self, OPENAI_SPARKLE_PUBLIC_KEY};
use super::{
    InstallOptions, InstallOutcome, InstallPhase, Source, StagingDir, download_to,
    ensure_free_space, ensure_not_cancelled, existing_codex_app, fatal, fetch_text, host_of,
    http_client, is_fatal, log_event, publish, set_phase,
};

/// OpenAI 的 Apple 开发者团队 ID（`Developer ID Application: OpenAI OpCo, LLC`）。
pub(crate) const OPENAI_TEAM_ID: &str = "2DC432GLL2";
/// Codex 桌面应用的 bundle id；新版 ChatGPT.app 沿用的就是它。
pub(crate) const CODEX_BUNDLE_ID: &str = "com.openai.codex";
/// 官方完整包里的应用名（Codex 并入 ChatGPT Desktop 后改叫 ChatGPT.app）。
const PACKAGED_APP_NAME: &str = "ChatGPT.app";

const MIRROR_APPCAST_ARM64: &str = "https://codexapp.agentsmirror.com/latest/appcast.xml";
const MIRROR_APPCAST_X64: &str = "https://codexapp.agentsmirror.com/latest/appcast-x64.xml";
const OFFICIAL_APPCAST_ARM64: &str = "https://persistent.oaistatic.com/codex-app-prod/appcast.xml";
const OFFICIAL_APPCAST_X64: &str =
    "https://persistent.oaistatic.com/codex-app-prod/appcast-x64.xml";

const CODESIGN: &str = "/usr/bin/codesign";
const DITTO: &str = "/usr/bin/ditto";
const PLIST_BUDDY: &str = "/usr/libexec/PlistBuddy";
const SPCTL: &str = "/usr/sbin/spctl";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MacArch {
    Arm64,
    X64,
}

impl MacArch {
    /// 与 appcast 的 `sparkle:hardwareRequirements` 取值一致。
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::X64 => "x86_64",
        }
    }

    /// 本机 CPU 架构。经 Rosetta 运行的 x86_64 进程也要认出 Apple Silicon，装原生版本。
    pub(crate) fn current() -> Self {
        if cfg!(target_arch = "aarch64") {
            return Self::Arm64;
        }
        match Command::new("/usr/sbin/sysctl")
            .args(["-n", "hw.optional.arm64"])
            .output()
        {
            Ok(output) if String::from_utf8_lossy(&output.stdout).trim() == "1" => Self::Arm64,
            _ => Self::X64,
        }
    }
}

pub(crate) fn appcast_url(source: Source, arch: MacArch) -> &'static str {
    match (source, arch) {
        (Source::Mirror, MacArch::Arm64) => MIRROR_APPCAST_ARM64,
        (Source::Mirror, MacArch::X64) => MIRROR_APPCAST_X64,
        (Source::Official, MacArch::Arm64) => OFFICIAL_APPCAST_ARM64,
        (Source::Official, MacArch::X64) => OFFICIAL_APPCAST_X64,
    }
}

/// 各下载源允许的安装包主机。验签已能兜住内容篡改，这里再拦住异常清单把下载引到无关主机。
pub(crate) fn enclosure_url_allowed(source: Source, url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let within = |domain: &str| host == domain || host.ends_with(&format!(".{domain}"));
    match source {
        Source::Mirror => within("agentsmirror.com"),
        Source::Official => within("oaistatic.com") || within("openai.com"),
    }
}

/// 暂存空间预算：压缩包 + 解压后的应用（约为压缩包的数倍），再留 512 MB 余量。
pub(crate) fn required_staging_space(package_len: u64) -> u64 {
    package_len
        .saturating_mul(4)
        .saturating_add(512 * 1024 * 1024)
}

/// 选源与校验策略；测试里可以换成自签的公钥和放行本地主机。
pub(crate) struct ArchivePolicy<'a> {
    pub(crate) arch: &'a str,
    pub(crate) os_version: Option<&'a str>,
    pub(crate) public_key: &'a str,
    pub(crate) url_allowed: fn(Source, &str) -> bool,
}

/// 通过 OpenAI 签名校验的完整包。
pub(crate) struct VerifiedArchive {
    pub(crate) path: PathBuf,
    pub(crate) source: Source,
    pub(crate) item: AppcastItem,
}

/// 依次尝试各下载源，返回第一个通过签名校验的完整包。
///
/// 换源能解决的问题（连不上、清单异常、下载中断、验签失败）继续试下一个源；
/// 换源也没用的问题（已取消、系统版本过低、磁盘不足）立即停止。
pub(crate) async fn fetch_verified_archive(
    client: &reqwest::Client,
    endpoints: &[(Source, String)],
    policy: &ArchivePolicy<'_>,
    staging: &Path,
) -> anyhow::Result<VerifiedArchive> {
    let mut failures = Vec::new();
    for (source, appcast_url) in endpoints {
        ensure_not_cancelled()?;
        match fetch_from_source(client, *source, appcast_url, policy, staging).await {
            Ok(archive) => return Ok(archive),
            Err(error) if is_fatal(&error) => return Err(error),
            Err(error) => {
                let detail = format!("{error:#}");
                log_event(
                    "codex_install.source_failed",
                    json!({ "source": source.id(), "error": detail }),
                );
                failures.push(format!("{}：{detail}", source.label()));
            }
        }
    }
    bail!("所有下载源都失败了。{}", failures.join("；"))
}

async fn fetch_from_source(
    client: &reqwest::Client,
    source: Source,
    appcast_url: &str,
    policy: &ArchivePolicy<'_>,
    staging: &Path,
) -> anyhow::Result<VerifiedArchive> {
    set_phase(InstallPhase::Resolving, source.resolving_message());
    let xml = fetch_text(client, appcast_url).await?;
    let items = appcast::parse_appcast(&xml)?;
    let item = appcast::latest(&items)
        .context("appcast 里没有可安装的版本")?
        .clone();
    if !(policy.url_allowed)(source, &item.url) {
        bail!("安装包地址（{}）不在可信主机名单内", host_of(&item.url));
    }
    if !appcast::hardware_supported(item.hardware_requirements.as_deref(), policy.arch) {
        bail!("该版本不支持当前 CPU 架构（{}）", policy.arch);
    }
    if let (Some(minimum), Some(current)) =
        (item.minimum_system_version.as_deref(), policy.os_version)
        && !appcast::version_at_least(current, minimum)
    {
        return Err(fatal(format!(
            "Codex {} 需要 macOS {minimum} 或更高版本，当前是 {current}",
            item.short_version
        )));
    }
    publish(|state| {
        state.source = Some(source.id().to_string());
        state.version = Some(item.short_version.clone());
    });
    ensure_free_space(staging, required_staging_space(item.length))?;

    let archive_path = staging.join(format!("codex-{}-{}.zip", source.id(), item.build));
    let downloaded = match download_to(
        client,
        &item.url,
        &archive_path,
        (item.length > 0).then_some(item.length),
    )
    .await
    {
        Ok(downloaded) => downloaded,
        Err(error) => {
            // 换下一个源前先删掉半截文件，免得两份大包同时占着磁盘。
            let _ = std::fs::remove_file(&archive_path);
            return Err(error);
        }
    };

    set_phase(InstallPhase::Verifying, "正在校验 OpenAI 签名…");
    let path = downloaded.path.clone();
    let signature = item.ed_signature.clone();
    let public_key = policy.public_key.to_string();
    let verified = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        // Sparkle 对整个文件签名，Ed25519 没法流式校验，只能整读进内存（约 700 MB，校验完即释放）。
        let bytes = std::fs::read(&path).context("读取安装包失败")?;
        sparkle::verify(&public_key, &bytes, &signature)
    })
    .await
    .context("签名校验任务异常退出")?;
    if let Err(error) = verified {
        let _ = std::fs::remove_file(&downloaded.path);
        return Err(error);
    }
    log_event(
        "codex_install.verified",
        json!({
            "source": source.id(),
            "version": item.short_version,
            "build": item.build,
            "bytes": downloaded.bytes,
            "sha256": downloaded.sha256,
        }),
    );
    Ok(VerifiedArchive {
        path: downloaded.path,
        source,
        item,
    })
}

pub(crate) async fn install(options: &InstallOptions) -> anyhow::Result<InstallOutcome> {
    if options.install_dir.is_none()
        && let Some(existing) = existing_codex_app()
    {
        return Err(fatal(format!(
            "已检测到 Codex：{}，无需重复安装",
            existing.display()
        )));
    }
    let install_dir = match &options.install_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("创建安装目录失败：{}", dir.display()))?;
            dir.clone()
        }
        None => choose_install_dir()?,
    };
    // 下载前先确认目标位置空着，免得下完 700 MB 才发现要覆盖别的应用。
    ensure_destination_free(&install_dir.join(PACKAGED_APP_NAME))?;

    let arch = MacArch::current();
    let os_version = product_version();
    let client = http_client()?;
    let staging = StagingDir::create(options)?;
    let endpoints = [Source::Mirror, Source::Official]
        .map(|source| (source, appcast_url(source, arch).to_string()));
    let policy = ArchivePolicy {
        arch: arch.label(),
        os_version: os_version.as_deref(),
        public_key: OPENAI_SPARKLE_PUBLIC_KEY,
        url_allowed: enclosure_url_allowed,
    };
    let archive = fetch_verified_archive(&client, &endpoints, &policy, staging.path()).await?;
    ensure_not_cancelled()?;

    set_phase(InstallPhase::Installing, "正在解压并校验应用签名…");
    let archive_path = archive.path.clone();
    let staging_path = staging.path().to_path_buf();
    let target_dir = install_dir.clone();
    let installed = tokio::task::spawn_blocking(move || {
        install_archive(&archive_path, &staging_path, &target_dir)
    })
    .await
    .context("安装任务异常退出")??;
    Ok(InstallOutcome {
        installed_path: installed.to_string_lossy().to_string(),
        version: archive.item.short_version,
        source: archive.source.id().to_string(),
    })
}

/// 解压、过签名闸、移入应用目录。阻塞执行，放在 `spawn_blocking` 里调用。
fn install_archive(archive: &Path, staging: &Path, install_dir: &Path) -> anyhow::Result<PathBuf> {
    let extract_dir = staging.join("extracted");
    std::fs::create_dir_all(&extract_dir)
        .with_context(|| format!("创建解压目录失败：{}", extract_dir.display()))?;
    // ditto 而不是 unzip：保留扩展属性与资源分支，签名才完整。
    run_tool(
        DITTO,
        &[
            OsStr::new("-x"),
            OsStr::new("-k"),
            archive.as_os_str(),
            extract_dir.as_os_str(),
        ],
    )
    .context("解压安装包失败")?;
    // 解压完就删压缩包，给后续复制腾出空间。
    let _ = std::fs::remove_file(archive);

    let app = single_app_bundle(&extract_dir)?;
    // 阶段保持「安装中」只换说明，界面进度条才不会从安装倒退回校验。
    set_phase(InstallPhase::Installing, "正在校验应用签名与公证…");
    gate_bundle(&app)?;
    let name = app.file_name().context("安装包里的应用名称异常")?;
    let destination = install_dir.join(name);
    ensure_destination_free(&destination)?;
    ensure_not_cancelled()?;
    set_phase(InstallPhase::Installing, "正在移入应用目录…");
    move_into_place(&app, &destination)?;
    Ok(destination)
}

/// 安装前的四道闸：签名完好、确实是 Codex、出自 OpenAI、Gatekeeper 放行（已公证）。
///
/// 前两道不能调换：codesign 校验通过后 Info.plist 已被签名封存，读出的 bundle id 才可信。
/// 只看 Team ID 不够：ChatGPT Classic（`com.openai.chat`）也是 OpenAI 团队签的。
fn gate_bundle(app: &Path) -> anyhow::Result<()> {
    run_tool(
        CODESIGN,
        &[
            OsStr::new("--verify"),
            OsStr::new("--deep"),
            OsStr::new("--strict"),
            app.as_os_str(),
        ],
    )
    .context("代码签名校验失败")?;
    let bundle_id = bundle_identifier(app)?;
    if bundle_id != CODEX_BUNDLE_ID {
        bail!("安装包的 bundle id 是 {bundle_id}，不是 Codex（{CODEX_BUNDLE_ID}）");
    }
    let output = run_tool(
        CODESIGN,
        &[
            OsStr::new("-dv"),
            OsStr::new("--verbose=2"),
            app.as_os_str(),
        ],
    )?;
    // `codesign -dv` 把字段打印在 stderr 上。
    let team = parse_team_identifier(&String::from_utf8_lossy(&output.stderr))
        .context("安装包签名里没有 TeamIdentifier")?;
    if team != OPENAI_TEAM_ID {
        bail!("安装包的签名团队是 {team}，不是 OpenAI（{OPENAI_TEAM_ID}）");
    }
    run_tool(
        SPCTL,
        &[
            OsStr::new("--assess"),
            OsStr::new("--type"),
            OsStr::new("execute"),
            app.as_os_str(),
        ],
    )
    .context("Gatekeeper 评估未通过（应用未公证或已损坏）")?;
    Ok(())
}

pub(crate) fn parse_team_identifier(codesign_output: &str) -> Option<String> {
    codesign_output
        .lines()
        .find_map(|line| line.trim().strip_prefix("TeamIdentifier="))
        .map(str::trim)
        .filter(|team| !team.is_empty() && *team != "not set")
        .map(str::to_string)
}

fn bundle_identifier(app: &Path) -> anyhow::Result<String> {
    let plist = app.join("Contents").join("Info.plist");
    let output = run_tool(
        PLIST_BUDDY,
        &[
            OsStr::new("-c"),
            OsStr::new("Print :CFBundleIdentifier"),
            plist.as_os_str(),
        ],
    )
    .context("读取应用的 bundle id 失败")?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// 解压结果里应当恰好有一个 `.app`。
pub(crate) fn single_app_bundle(dir: &Path) -> anyhow::Result<PathBuf> {
    let mut apps = std::fs::read_dir(dir)
        .with_context(|| format!("读取解压目录失败：{}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir() && path.extension() == Some(OsStr::new("app")))
        .collect::<Vec<_>>();
    match apps.len() {
        1 => Ok(apps.remove(0)),
        0 => bail!("安装包里没有找到应用"),
        count => bail!("安装包里有 {count} 个应用，结构异常"),
    }
}

/// 目标位置已被占用时停止：既然没探测到 Codex，那里放的就是别的应用（比如改名后的
/// ChatGPT Classic），绝不能覆盖。
pub(crate) fn ensure_destination_free(destination: &Path) -> anyhow::Result<()> {
    if !destination.exists() {
        return Ok(());
    }
    let identity = bundle_identifier(destination)
        .ok()
        .filter(|id| !id.is_empty())
        .map(|id| format!("（bundle id {id}）"))
        .unwrap_or_default();
    Err(fatal(format!(
        "{} 已存在{identity}，但它不是可识别的 Codex。为避免覆盖，请先把它改名或移走后重试。",
        destination.display()
    )))
}

/// 优先 rename（同一个卷上是原子操作）；暂存目录与应用目录不在同一个卷时改用 ditto 复制
/// （保留签名与扩展属性），复制后再校验一次签名。复制中途失败就删掉复制了一半的目标——
/// 安装前已确认它原本不存在，删的只会是这次写入的内容。
fn move_into_place(staged: &Path, destination: &Path) -> anyhow::Result<()> {
    let Err(rename_error) = std::fs::rename(staged, destination) else {
        return Ok(());
    };
    let copied = run_tool(DITTO, &[staged.as_os_str(), destination.as_os_str()]).and_then(|_| {
        run_tool(
            CODESIGN,
            &[
                OsStr::new("--verify"),
                OsStr::new("--deep"),
                OsStr::new("--strict"),
                destination.as_os_str(),
            ],
        )
    });
    if let Err(error) = copied {
        let _ = std::fs::remove_dir_all(destination);
        return Err(error.context(format!(
            "移入 {} 失败（直接移动也失败：{rename_error}）",
            destination.display()
        )));
    }
    Ok(())
}

/// `/Applications` 可写就装到那里；否则（非管理员、受管设备）退到无需提权的 `~/Applications`。
fn choose_install_dir() -> anyhow::Result<PathBuf> {
    let system = PathBuf::from("/Applications");
    if dir_writable(&system) {
        return Ok(system);
    }
    let home = directories::BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .context("找不到用户主目录")?;
    let user_apps = home.join("Applications");
    std::fs::create_dir_all(&user_apps)
        .with_context(|| format!("创建 {} 失败", user_apps.display()))?;
    Ok(user_apps)
}

pub(crate) fn dir_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".codex-plus-write-probe-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn product_version() -> Option<String> {
    let output = Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .ok()?;
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (output.status.success() && !version.is_empty()).then_some(version)
}

fn run_tool(program: &str, args: &[&OsStr]) -> anyhow::Result<Output> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("无法运行 {program}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("无错误输出");
        bail!("{program} 执行失败（{}）：{detail}", output.status);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn signing_key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap()
    }

    fn appcast(build: u64, url: &str, payload: &[u8], signature: &str) -> String {
        format!(
            r#"<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item>
<sparkle:version>{build}</sparkle:version>
<sparkle:shortVersionString>26.1.{build}</sparkle:shortVersionString>
<sparkle:minimumSystemVersion>13.0</sparkle:minimumSystemVersion>
<enclosure url="{url}" length="{}" sparkle:edSignature="{signature}" />
</item></channel></rss>"#,
            payload.len()
        )
    }

    fn allow_any(_: Source, _: &str) -> bool {
        true
    }

    async fn mount(server: &MockServer, route: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(response)
            .mount(server)
            .await;
    }

    #[test]
    fn appcast_urls_follow_source_and_architecture() {
        assert_eq!(
            appcast_url(Source::Mirror, MacArch::Arm64),
            "https://codexapp.agentsmirror.com/latest/appcast.xml"
        );
        assert_eq!(
            appcast_url(Source::Official, MacArch::X64),
            "https://persistent.oaistatic.com/codex-app-prod/appcast-x64.xml"
        );
    }

    #[test]
    fn enclosure_hosts_are_pinned_per_source() {
        let mirror = "https://codexapp.agentsmirror.com/latest/mac/arm64/Codex.zip";
        let official = "https://persistent.oaistatic.com/codex-app-prod/ChatGPT.zip";
        assert!(enclosure_url_allowed(Source::Mirror, mirror));
        assert!(enclosure_url_allowed(Source::Official, official));
        assert!(!enclosure_url_allowed(Source::Mirror, official));
        assert!(!enclosure_url_allowed(Source::Official, mirror));
        assert!(!enclosure_url_allowed(
            Source::Mirror,
            "http://codexapp.agentsmirror.com/a.zip"
        ));
        assert!(!enclosure_url_allowed(
            Source::Mirror,
            "https://agentsmirror.com.evil.test/a.zip"
        ));
    }

    #[tokio::test]
    async fn falls_back_to_official_when_mirror_is_unreachable() {
        let server = MockServer::start().await;
        let key = signing_key();
        let payload = b"official codex package".to_vec();
        let signature = STANDARD.encode(key.sign(&payload).as_ref());
        let url = format!("{}/official/pkg.zip", server.uri());
        mount(&server, "/mirror/appcast.xml", ResponseTemplate::new(503)).await;
        mount(
            &server,
            "/official/appcast.xml",
            ResponseTemplate::new(200).set_body_string(appcast(7, &url, &payload, &signature)),
        )
        .await;
        mount(
            &server,
            "/official/pkg.zip",
            ResponseTemplate::new(200).set_body_bytes(payload.clone()),
        )
        .await;
        let staging = tempfile::tempdir().unwrap();
        let public_key = STANDARD.encode(key.public_key().as_ref());
        let policy = ArchivePolicy {
            arch: "arm64",
            os_version: Some("15.0"),
            public_key: &public_key,
            url_allowed: allow_any,
        };
        let endpoints = [
            (
                Source::Mirror,
                format!("{}/mirror/appcast.xml", server.uri()),
            ),
            (
                Source::Official,
                format!("{}/official/appcast.xml", server.uri()),
            ),
        ];

        let archive =
            fetch_verified_archive(&http_client().unwrap(), &endpoints, &policy, staging.path())
                .await
                .unwrap();

        assert_eq!(archive.source, Source::Official);
        assert_eq!(archive.item.build, 7);
        assert_eq!(std::fs::read(&archive.path).unwrap(), payload);
    }

    #[tokio::test]
    async fn tampered_mirror_package_is_rejected_and_official_is_used() {
        let server = MockServer::start().await;
        let key = signing_key();
        let genuine = b"genuine codex package".to_vec();
        let signature = STANDARD.encode(key.sign(&genuine).as_ref());
        // 镜像给出的签名是真的，但包内容被替换了：验签必须失败并回退到官方源。
        let mirror_url = format!("{}/mirror/pkg.zip", server.uri());
        let official_url = format!("{}/official/pkg.zip", server.uri());
        mount(
            &server,
            "/mirror/appcast.xml",
            ResponseTemplate::new(200).set_body_string(appcast(
                9,
                &mirror_url,
                &genuine,
                &signature,
            )),
        )
        .await;
        mount(
            &server,
            "/mirror/pkg.zip",
            ResponseTemplate::new(200).set_body_bytes(b"tampered codex packag".to_vec()),
        )
        .await;
        mount(
            &server,
            "/official/appcast.xml",
            ResponseTemplate::new(200).set_body_string(appcast(
                9,
                &official_url,
                &genuine,
                &signature,
            )),
        )
        .await;
        mount(
            &server,
            "/official/pkg.zip",
            ResponseTemplate::new(200).set_body_bytes(genuine.clone()),
        )
        .await;
        let staging = tempfile::tempdir().unwrap();
        let public_key = STANDARD.encode(key.public_key().as_ref());
        let policy = ArchivePolicy {
            arch: "arm64",
            os_version: Some("15.0"),
            public_key: &public_key,
            url_allowed: allow_any,
        };
        let endpoints = [
            (
                Source::Mirror,
                format!("{}/mirror/appcast.xml", server.uri()),
            ),
            (
                Source::Official,
                format!("{}/official/appcast.xml", server.uri()),
            ),
        ];

        let archive =
            fetch_verified_archive(&http_client().unwrap(), &endpoints, &policy, staging.path())
                .await
                .unwrap();

        assert_eq!(archive.source, Source::Official);
        assert_eq!(std::fs::read(&archive.path).unwrap(), genuine);
        assert!(
            !staging.path().join("codex-mirror-9.zip").exists(),
            "验签失败的镜像包要删掉"
        );
    }

    #[tokio::test]
    async fn outdated_macos_stops_without_trying_other_sources() {
        let server = MockServer::start().await;
        let key = signing_key();
        let payload = b"pkg".to_vec();
        let signature = STANDARD.encode(key.sign(&payload).as_ref());
        let url = format!("{}/pkg.zip", server.uri());
        mount(
            &server,
            "/mirror/appcast.xml",
            ResponseTemplate::new(200).set_body_string(appcast(3, &url, &payload, &signature)),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/official/appcast.xml"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let staging = tempfile::tempdir().unwrap();
        let public_key = STANDARD.encode(key.public_key().as_ref());
        let policy = ArchivePolicy {
            arch: "arm64",
            os_version: Some("12.7.6"),
            public_key: &public_key,
            url_allowed: allow_any,
        };
        let endpoints = [
            (
                Source::Mirror,
                format!("{}/mirror/appcast.xml", server.uri()),
            ),
            (
                Source::Official,
                format!("{}/official/appcast.xml", server.uri()),
            ),
        ];

        let error =
            fetch_verified_archive(&http_client().unwrap(), &endpoints, &policy, staging.path())
                .await
                .err()
                .unwrap();

        assert!(is_fatal(&error));
        assert!(
            format!("{error:#}").contains("需要 macOS 13.0"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn reports_every_source_when_all_fail() {
        let server = MockServer::start().await;
        mount(&server, "/mirror/appcast.xml", ResponseTemplate::new(500)).await;
        mount(
            &server,
            "/official/appcast.xml",
            ResponseTemplate::new(200).set_body_string("<rss></rss>"),
        )
        .await;
        let staging = tempfile::tempdir().unwrap();
        let policy = ArchivePolicy {
            arch: "arm64",
            os_version: None,
            public_key: OPENAI_SPARKLE_PUBLIC_KEY,
            url_allowed: allow_any,
        };
        let endpoints = [
            (
                Source::Mirror,
                format!("{}/mirror/appcast.xml", server.uri()),
            ),
            (
                Source::Official,
                format!("{}/official/appcast.xml", server.uri()),
            ),
        ];

        let error =
            fetch_verified_archive(&http_client().unwrap(), &endpoints, &policy, staging.path())
                .await
                .err()
                .unwrap();
        let message = format!("{error:#}");

        assert!(message.contains("镜像源"), "{message}");
        assert!(message.contains("OpenAI 官方源"), "{message}");
    }

    #[test]
    fn finds_the_single_app_bundle() {
        let temp = tempfile::tempdir().unwrap();
        assert!(single_app_bundle(temp.path()).is_err());
        std::fs::create_dir_all(temp.path().join("ChatGPT.app/Contents")).unwrap();
        std::fs::write(temp.path().join("notes.txt"), b"x").unwrap();
        assert_eq!(
            single_app_bundle(temp.path()).unwrap(),
            temp.path().join("ChatGPT.app")
        );
        std::fs::create_dir_all(temp.path().join("Other.app")).unwrap();
        assert!(single_app_bundle(temp.path()).is_err());
    }

    #[test]
    fn occupied_destination_stops_installation() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("ChatGPT.app");
        assert!(ensure_destination_free(&destination).is_ok());
        std::fs::create_dir_all(&destination).unwrap();

        let error = ensure_destination_free(&destination).unwrap_err();

        assert!(is_fatal(&error));
        assert!(error.to_string().contains("为避免覆盖"));
    }

    #[test]
    fn reads_team_identifier_from_codesign_output() {
        let output = "Executable=/Applications/ChatGPT.app/Contents/MacOS/ChatGPT\nIdentifier=com.openai.codex\nTeamIdentifier=2DC432GLL2\n";
        assert_eq!(parse_team_identifier(output).as_deref(), Some("2DC432GLL2"));
        assert_eq!(parse_team_identifier("TeamIdentifier=not set\n"), None);
        assert_eq!(parse_team_identifier("Identifier=x\n"), None);
    }

    #[test]
    fn detects_writable_directories() {
        let temp = tempfile::tempdir().unwrap();
        assert!(dir_writable(temp.path()));
        assert!(!dir_writable(&temp.path().join("missing")));
        assert_eq!(
            std::fs::read_dir(temp.path()).unwrap().count(),
            0,
            "探针文件要删干净"
        );
    }

    #[test]
    fn staging_budget_covers_archive_and_extraction() {
        assert_eq!(required_staging_space(1024), 4096 + 512 * 1024 * 1024);
        assert_eq!(required_staging_space(u64::MAX), u64::MAX);
    }
}
