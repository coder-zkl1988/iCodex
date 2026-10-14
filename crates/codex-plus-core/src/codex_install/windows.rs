//! Windows 安装：镜像清单 → 下载 MSIX → SHA-256 / 包身份 / Authenticode 校验 → `Add-AppxPackage`。
//!
//! Windows 版 Codex 官方只通过微软商店分发；镜像提供的是商店包的字节级副本（微软商店重签名），
//! 镜像不可用时由界面引导用户去商店安装。所有平台都参与编译，只在 Windows 上调用。
#![cfg_attr(not(windows), allow(dead_code))]

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use quick_xml::Reader;
use quick_xml::events::Event;
use serde_json::Value;

use super::{
    InstallOptions, InstallOutcome, InstallPhase, Source, StagingDir, download_to,
    ensure_free_space, ensure_not_cancelled, existing_codex_app, fatal, fetch_text, http_client,
    publish, set_phase,
};

pub const STORE_PRODUCT_ID: &str = "9PLM9XGG6VKS";
pub const STORE_DEEP_LINK: &str = "ms-windows-store://pdp/?productid=9PLM9XGG6VKS";
pub const STORE_WEB_URL: &str = "https://apps.microsoft.com/detail/9PLM9XGG6VKS";

const MIRROR_BASE_URL: &str = "https://codexapp.agentsmirror.com";
const PACKAGE_NAME: &str = "OpenAI.Codex";
/// `OpenAI.Codex_<版本>_<架构>__2p2nqsd0c76g0` 末尾的发布者哈希。
const PACKAGE_PUBLISHER_ID: &str = "2p2nqsd0c76g0";
/// 微软商店为 OpenAI 重签名时使用的发布者证书主题（商店发布者 ID）。
const STORE_SIGNER_SUBJECT: &str = "CN=50bdfd77-8903-4850-9ffe-6e8522f64d5b";
const STORE_ISSUER_CN_PREFIX: &str = "CN=Microsoft Marketplace CA";
const STORE_ISSUER_ORG: &str = "O=Microsoft Corporation";
const MANIFEST_MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WinArch {
    X64,
    Arm64,
}

impl WinArch {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
        }
    }

    pub(crate) fn from_processor_architecture(value: Option<&str>) -> Self {
        if value.is_some_and(|value| value.trim().eq_ignore_ascii_case("ARM64")) {
            Self::Arm64
        } else {
            Self::X64
        }
    }

    /// 本机 CPU 架构；32 位进程看 `PROCESSOR_ARCHITEW6432` 才能拿到真实架构。
    pub(crate) fn current() -> Self {
        if cfg!(target_arch = "aarch64") {
            return Self::Arm64;
        }
        let native = std::env::var("PROCESSOR_ARCHITEW6432")
            .or_else(|_| std::env::var("PROCESSOR_ARCHITECTURE"))
            .ok();
        Self::from_processor_architecture(native.as_deref())
    }
}

pub(crate) fn manifest_url() -> String {
    format!("{MIRROR_BASE_URL}/latest/manifest")
}

pub(crate) fn checksums_url() -> String {
    format!("{MIRROR_BASE_URL}/latest/checksums")
}

pub(crate) fn package_url(arch: WinArch) -> String {
    format!("{MIRROR_BASE_URL}/latest/win-{}", arch.label())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsRelease {
    /// 四段式 MSIX 包版本，如 `26.1007.9446.0`。
    pub(crate) package_version: String,
    /// 展示给用户的 Codex 版本，如 `26.1007.71326`。
    pub(crate) app_version: String,
    pub(crate) package_moniker: String,
    pub(crate) content_length: Option<u64>,
}

pub(crate) fn expected_moniker(package_version: &str, arch: WinArch) -> String {
    format!(
        "{PACKAGE_NAME}_{package_version}_{}__{PACKAGE_PUBLISHER_ID}",
        arch.label()
    )
}

/// 读出镜像清单里当前架构的 MSIX 信息，并核对包标识的格式。
pub(crate) fn parse_manifest(text: &str, arch: WinArch) -> anyhow::Result<WindowsRelease> {
    let manifest: Value = serde_json::from_str(text).context("镜像清单不是合法的 JSON")?;
    let schema = manifest
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if schema < 2 {
        bail!("不支持的镜像清单版本：{schema}");
    }
    let windows = manifest
        .pointer("/sources/windows")
        .context("镜像清单里没有 Windows 安装包信息")?;
    let entry = windows
        .get("architectures")
        .and_then(|architectures| architectures.get(arch.label()))
        .with_context(|| format!("镜像清单里没有 {} 架构的安装包", arch.label()))?;
    if entry.get("downloadable").and_then(Value::as_bool) == Some(false) {
        bail!("镜像暂未提供 {} 架构的安装包", arch.label());
    }
    let package_version = entry
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .context("镜像清单缺少安装包版本")?
        .to_string();
    let moniker = entry
        .get("packageMoniker")
        .and_then(Value::as_str)
        .map(str::trim)
        .context("镜像清单缺少安装包标识")?;
    let expected = expected_moniker(&package_version, arch);
    if !moniker.eq_ignore_ascii_case(&expected) {
        bail!("镜像清单的安装包标识异常：{moniker}（应为 {expected}）");
    }
    let app_version = [
        entry.get("appVersion"),
        windows.get("appVersion"),
        manifest.get("codexVersion"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .map(str::trim)
    .find(|version| !version.is_empty())
    .unwrap_or(&package_version)
    .to_string();
    Ok(WindowsRelease {
        package_version,
        app_version,
        package_moniker: expected,
        content_length: entry
            .get("contentLength")
            .and_then(Value::as_u64)
            .filter(|length| *length > 0),
    })
}

/// 在 `sha256sum` 格式的校验清单里找指定文件的 SHA-256；缺失、重复或格式异常都算失败。
pub(crate) fn find_checksum(text: &str, file_name: &str) -> anyhow::Result<String> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((hash, name)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let name = name.trim().trim_start_matches('*');
        if !name.eq_ignore_ascii_case(file_name) {
            continue;
        }
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("校验清单里 {file_name} 的 SHA-256 格式异常");
        }
        if found.is_some() {
            bail!("校验清单里 {file_name} 出现了多次");
        }
        found = Some(hash.to_ascii_lowercase());
    }
    found.with_context(|| format!("校验清单里没有 {file_name}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MsixIdentity {
    pub(crate) name: String,
    pub(crate) publisher: String,
    pub(crate) version: String,
    pub(crate) architecture: String,
}

/// 从 AppxManifest.xml 读出包身份（第一个 `<Identity>` 元素）。
pub(crate) fn parse_appx_identity(xml: &str) -> anyhow::Result<MsixIdentity> {
    let mut reader = Reader::from_str(xml);
    loop {
        match reader
            .read_event()
            .context("AppxManifest.xml 不是合法的 XML")?
        {
            Event::Start(element) | Event::Empty(element)
                if element.local_name().as_ref() == b"Identity" =>
            {
                let mut identity = MsixIdentity {
                    name: String::new(),
                    publisher: String::new(),
                    version: String::new(),
                    architecture: String::new(),
                };
                for attribute in element.attributes() {
                    let attribute = attribute.context("Identity 属性格式异常")?;
                    let value = attribute
                        .unescape_value()
                        .context("Identity 属性编码异常")?
                        .trim()
                        .to_string();
                    match attribute.key.local_name().as_ref() {
                        b"Name" => identity.name = value,
                        b"Publisher" => identity.publisher = value,
                        b"Version" => identity.version = value,
                        b"ProcessorArchitecture" => identity.architecture = value,
                        _ => {}
                    }
                }
                return Ok(identity);
            }
            Event::Eof => bail!("AppxManifest.xml 里没有 Identity"),
            _ => {}
        }
    }
}

/// MSIX 本质是 zip，包身份在根目录的 AppxManifest.xml 里。
pub(crate) fn read_msix_identity(path: &Path) -> anyhow::Result<MsixIdentity> {
    let file =
        std::fs::File::open(path).with_context(|| format!("打开安装包失败：{}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("安装包不是合法的 MSIX")?;
    let mut entry = archive
        .by_name("AppxManifest.xml")
        .context("安装包里缺少 AppxManifest.xml")?;
    if entry.size() > MANIFEST_MAX_BYTES {
        bail!("安装包的 AppxManifest.xml 过大");
    }
    let mut xml = String::new();
    entry
        .read_to_string(&mut xml)
        .context("读取 AppxManifest.xml 失败")?;
    parse_appx_identity(&xml)
}

pub(crate) fn validate_identity(
    identity: &MsixIdentity,
    release: &WindowsRelease,
    arch: WinArch,
) -> anyhow::Result<()> {
    if identity.name != PACKAGE_NAME {
        bail!("安装包身份是 {}，不是 {PACKAGE_NAME}", identity.name);
    }
    if identity.version != release.package_version {
        bail!(
            "安装包版本 {} 与镜像清单 {} 不一致",
            identity.version,
            release.package_version
        );
    }
    if !identity.architecture.eq_ignore_ascii_case(arch.label()) {
        bail!(
            "安装包架构 {} 与本机 {} 不一致",
            identity.architecture,
            arch.label()
        );
    }
    Ok(())
}

fn distinguished_name_parts(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|part| part.trim().to_ascii_lowercase())
        .filter(|part| !part.is_empty())
        .collect()
}

/// Authenticode 结果是否为「微软商店为 OpenAI 签发的有效签名」。
pub(crate) fn store_signature_trusted(status: &str, subject: &str, issuer: &str) -> bool {
    let issuer = distinguished_name_parts(issuer);
    let issuer_cn = STORE_ISSUER_CN_PREFIX.to_ascii_lowercase();
    let issuer_org = STORE_ISSUER_ORG.to_ascii_lowercase();
    status.trim().eq_ignore_ascii_case("Valid")
        && distinguished_name_parts(subject) == distinguished_name_parts(STORE_SIGNER_SUBJECT)
        && issuer.iter().any(|part| part.starts_with(&issuer_cn))
        && issuer.iter().any(|part| *part == issuer_org)
}

pub(crate) async fn install(options: &InstallOptions) -> anyhow::Result<InstallOutcome> {
    if let Some(existing) = existing_codex_app() {
        return Err(fatal(format!(
            "已检测到 Codex：{}，无需重复安装",
            existing.display()
        )));
    }
    let arch = WinArch::current();
    let client = http_client()?;
    let staging = StagingDir::create(options)?;

    set_phase(InstallPhase::Resolving, Source::Mirror.resolving_message());
    let manifest = fetch_text(&client, &manifest_url()).await?;
    let checksums = fetch_text(&client, &checksums_url()).await?;
    let release = parse_manifest(&manifest, arch)?;
    let file_name = format!("{}.Msix", release.package_moniker);
    let expected_sha256 = find_checksum(&checksums, &file_name)?;
    publish(|state| {
        state.source = Some(Source::Mirror.id().to_string());
        state.version = Some(release.app_version.clone());
    });
    if let Some(length) = release.content_length {
        // 下载的 MSIX + Windows 解包安装的副本，再留 512 MB 余量。
        ensure_free_space(
            staging.path(),
            length.saturating_mul(3).saturating_add(512 * 1024 * 1024),
        )?;
    }

    let package_path = staging.path().join(&file_name);
    let downloaded = download_to(
        &client,
        &package_url(arch),
        &package_path,
        release.content_length,
    )
    .await?;
    set_phase(InstallPhase::Verifying, "正在校验安装包签名…");
    if !downloaded.sha256.eq_ignore_ascii_case(&expected_sha256) {
        bail!("安装包的 SHA-256 与镜像清单不一致（镜像可能正在更新，请稍后重试）");
    }
    let verify_path = package_path.clone();
    let verify_release = release.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let identity = read_msix_identity(&verify_path)?;
        validate_identity(&identity, &verify_release, arch)?;
        verify_authenticode(&verify_path)
    })
    .await
    .context("校验任务异常退出")??;
    ensure_not_cancelled()?;

    set_phase(InstallPhase::Installing, "正在调用 Windows 安装 Codex…");
    let install_path = package_path.clone();
    let location = tokio::task::spawn_blocking(move || add_appx_package(&install_path))
        .await
        .context("安装任务异常退出")??;
    Ok(InstallOutcome {
        installed_path: location.unwrap_or_else(|| release.package_moniker.clone()),
        version: release.app_version,
        source: Source::Mirror.id().to_string(),
    })
}

fn verify_authenticode(path: &Path) -> anyhow::Result<()> {
    let output = run_powershell(&authenticode_script(path)?)?;
    if !output.status.success() {
        bail!(
            "读取安装包签名失败：{}",
            first_lines(&String::from_utf8_lossy(&output.stderr))
        );
    }
    let report: Value = serde_json::from_slice(&output.stdout).context("签名检查结果格式异常")?;
    let field = |key: &str| report.get(key).and_then(Value::as_str).unwrap_or_default();
    if !store_signature_trusted(field("status"), field("subject"), field("issuer")) {
        bail!(
            "安装包不是微软商店为 OpenAI 签发的有效签名（状态 {}，签名者 {}）",
            field("status"),
            field("subject")
        );
    }
    Ok(())
}

/// 返回安装位置（读不到时为 None）。失败时给出 Add-AppxPackage 的原始报错，界面会引导去商店安装。
fn add_appx_package(path: &Path) -> anyhow::Result<Option<String>> {
    let output = run_powershell(&add_appx_script(path)?)?;
    if !output.status.success() {
        bail!(
            "Add-AppxPackage 安装失败：{}",
            first_lines(&String::from_utf8_lossy(&output.stderr))
        );
    }
    Ok(parse_install_location(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

pub(crate) fn parse_install_location(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("INSTALL_LOCATION="))
        .map(str::trim)
        .filter(|location| !location.is_empty())
        .map(str::to_string)
}

/// 单引号字面量：PowerShell 单引号字符串里只有 `'` 需要转义（写成 `''`）。
pub(crate) fn powershell_literal(value: &str) -> anyhow::Result<String> {
    if value.is_empty() || value.contains(['\r', '\n', '\0']) {
        bail!("参数里有无法安全传给 PowerShell 的字符：{value:?}");
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

/// 显式导入安全模块：模块自动加载在部分受管系统上被关掉，`Get-AuthenticodeSignature` 会找不到。
pub(crate) fn authenticode_script(path: &Path) -> anyhow::Result<String> {
    let path = powershell_literal(&path.to_string_lossy())?;
    Ok(format!(
        r#"$ErrorActionPreference = 'Stop'
$securityModule = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
if (Test-Path -LiteralPath $securityModule) {{ Import-Module $securityModule }}
$sig = Get-AuthenticodeSignature -LiteralPath {path}
@{{
  status = [string]$sig.Status
  subject = if ($sig.SignerCertificate) {{ [string]$sig.SignerCertificate.Subject }} else {{ '' }}
  issuer = if ($sig.SignerCertificate) {{ [string]$sig.SignerCertificate.Issuer }} else {{ '' }}
}} | ConvertTo-Json -Compress"#
    ))
}

/// 新版 Appx 模块支持 `-LiteralPath`（不按通配符解析路径），旧版只有 `-Path`。
pub(crate) fn add_appx_script(path: &Path) -> anyhow::Result<String> {
    let path = powershell_literal(&path.to_string_lossy())?;
    Ok(format!(
        r#"$ErrorActionPreference = 'Stop'
$command = Get-Command Add-AppxPackage
$arguments = @{{ ErrorAction = 'Stop' }}
if ($command.Parameters.Keys -contains 'LiteralPath') {{ $arguments['LiteralPath'] = {path} }} else {{ $arguments['Path'] = {path} }}
Add-AppxPackage @arguments
$package = Get-AppxPackage -Name '{PACKAGE_NAME}' | Sort-Object -Property Version -Descending | Select-Object -First 1
if ($package) {{ "INSTALL_LOCATION=$($package.InstallLocation)" }}"#
    ))
}

fn powershell_exe() -> PathBuf {
    std::env::var_os("WINDIR")
        .map(|windir| {
            PathBuf::from(windir)
                .join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")
        })
        .filter(|path| path.exists())
        .unwrap_or_else(|| PathBuf::from("powershell.exe"))
}

fn run_powershell(script: &str) -> anyhow::Result<std::process::Output> {
    let mut command = std::process::Command::new(powershell_exe());
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(crate::windows_integration::CREATE_NO_WINDOW);
    }
    command.output().context("启动 powershell.exe 失败")
}

fn first_lines(text: &str) -> String {
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(3)
        .collect::<Vec<_>>();
    if lines.is_empty() {
        "无错误输出".to_string()
    } else {
        lines.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // 结构取自真实镜像清单（裁掉了无关字段）。
    const MANIFEST: &str = r#"{
      "schemaVersion": 5,
      "codexVersion": "26.1007.71326",
      "sources": {
        "windows": {
          "productId": "9PLM9XGG6VKS",
          "version": "26.1007.9446.0",
          "appVersion": "26.1007.71326",
          "architectures": {
            "x64": {
              "downloadable": true,
              "version": "26.1007.9446.0",
              "packageMoniker": "OpenAI.Codex_26.1007.9446.0_x64__2p2nqsd0c76g0",
              "contentLength": 944929441,
              "appVersion": "26.1007.71326"
            },
            "arm64": {
              "downloadable": true,
              "version": "26.1007.9446.0",
              "packageMoniker": "OpenAI.Codex_26.1007.9446.0_arm64__2p2nqsd0c76g0",
              "contentLength": 1017778154
            }
          }
        }
      }
    }"#;

    const CHECKSUMS: &str = "4ab4d4569c5728ab0c6d314ce0ab0dcb84f861378a7a9bb2360100021b15a4cc  Codex-mac-arm64.dmg
230573079dc6ec7060c76778d470c029be90dddcc1efcb79427a3620864c816e  OpenAI.Codex_26.1007.9446.0_x64__2p2nqsd0c76g0.Msix
5d9f5ebb5fad3581895effecea052308055955815ca24c2f66faa0fea762e0dc  OpenAI.Codex_26.1007.9446.0_arm64__2p2nqsd0c76g0.Msix
";

    const APPX_MANIFEST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="OpenAI.Codex" Publisher="CN=50bdfd77-8903-4850-9ffe-6e8522f64d5b" Version="26.1007.9446.0" ProcessorArchitecture="x64" />
  <Dependencies>
    <PackageDependency Name="Microsoft.VCLibs.140.00.UWPDesktop" MinVersion="14.0.0.0" />
  </Dependencies>
</Package>"#;

    #[test]
    fn parses_manifest_for_each_architecture() {
        let x64 = parse_manifest(MANIFEST, WinArch::X64).unwrap();
        assert_eq!(x64.package_version, "26.1007.9446.0");
        assert_eq!(x64.app_version, "26.1007.71326");
        assert_eq!(
            x64.package_moniker,
            "OpenAI.Codex_26.1007.9446.0_x64__2p2nqsd0c76g0"
        );
        assert_eq!(x64.content_length, Some(944_929_441));

        let arm64 = parse_manifest(MANIFEST, WinArch::Arm64).unwrap();
        assert_eq!(
            arm64.package_moniker,
            "OpenAI.Codex_26.1007.9446.0_arm64__2p2nqsd0c76g0"
        );
        // 架构条目没写 appVersion 时回退到 Windows 节点上的值。
        assert_eq!(arm64.app_version, "26.1007.71326");
    }

    #[test]
    fn rejects_unexpected_manifests() {
        let tampered = MANIFEST.replace(
            "OpenAI.Codex_26.1007.9446.0_x64__2p2nqsd0c76g0",
            "Evil.Package_26.1007.9446.0_x64__2p2nqsd0c76g0",
        );
        assert!(parse_manifest(&tampered, WinArch::X64).is_err());

        let unavailable = MANIFEST.replacen("\"downloadable\": true", "\"downloadable\": false", 1);
        assert!(parse_manifest(&unavailable, WinArch::X64).is_err());

        let old_schema = MANIFEST.replace("\"schemaVersion\": 5", "\"schemaVersion\": 1");
        assert!(parse_manifest(&old_schema, WinArch::X64).is_err());
        assert!(parse_manifest("not json", WinArch::X64).is_err());
    }

    #[test]
    fn finds_checksum_by_exact_file_name() {
        assert_eq!(
            find_checksum(
                CHECKSUMS,
                "OpenAI.Codex_26.1007.9446.0_x64__2p2nqsd0c76g0.Msix"
            )
            .unwrap(),
            "230573079dc6ec7060c76778d470c029be90dddcc1efcb79427a3620864c816e"
        );
        assert!(find_checksum(CHECKSUMS, "OpenAI.Codex_1.0.0.0_x64__2p2nqsd0c76g0.Msix").is_err());

        let duplicated = format!(
            "{CHECKSUMS}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  Codex-mac-arm64.dmg\n"
        );
        assert!(find_checksum(&duplicated, "Codex-mac-arm64.dmg").is_err());
        assert!(find_checksum("xyz  Codex-mac-arm64.dmg", "Codex-mac-arm64.dmg").is_err());
    }

    #[test]
    fn reads_identity_from_msix_archive() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("package.Msix");
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        writer
            .start_file(
                "AppxManifest.xml",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(APPX_MANIFEST.as_bytes()).unwrap();
        writer.finish().unwrap();

        let identity = read_msix_identity(&path).unwrap();
        assert_eq!(identity.name, "OpenAI.Codex");
        assert_eq!(identity.version, "26.1007.9446.0");
        assert_eq!(identity.architecture, "x64");

        let release = parse_manifest(MANIFEST, WinArch::X64).unwrap();
        assert!(validate_identity(&identity, &release, WinArch::X64).is_ok());
        assert!(validate_identity(&identity, &release, WinArch::Arm64).is_err());
        let mut other = identity.clone();
        other.name = "Contoso.App".to_string();
        assert!(validate_identity(&other, &release, WinArch::X64).is_err());
    }

    #[test]
    fn rejects_archives_without_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("package.Msix");
        std::fs::write(&path, b"not a zip").unwrap();
        assert!(read_msix_identity(&path).is_err());
        assert!(parse_appx_identity("<Package></Package>").is_err());
    }

    #[test]
    fn trusts_only_store_signatures_for_openai() {
        let subject = "CN=50bdfd77-8903-4850-9ffe-6e8522f64d5b";
        let issuer = "CN=Microsoft Marketplace CA G 027, OU=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
        assert!(store_signature_trusted("Valid", subject, issuer));
        assert!(store_signature_trusted(
            "valid",
            &subject.to_lowercase(),
            issuer
        ));
        assert!(!store_signature_trusted("HashMismatch", subject, issuer));
        assert!(!store_signature_trusted(
            "Valid",
            "CN=OpenAI OpCo, LLC, O=OpenAI OpCo, LLC, C=US",
            issuer
        ));
        assert!(!store_signature_trusted(
            "Valid",
            subject,
            "CN=Some Other CA, O=Microsoft Corporation"
        ));
    }

    #[test]
    fn detects_native_architecture() {
        assert_eq!(
            WinArch::from_processor_architecture(Some("ARM64")),
            WinArch::Arm64
        );
        assert_eq!(
            WinArch::from_processor_architecture(Some("AMD64")),
            WinArch::X64
        );
        assert_eq!(WinArch::from_processor_architecture(None), WinArch::X64);
        assert_eq!(
            package_url(WinArch::Arm64),
            "https://codexapp.agentsmirror.com/latest/win-arm64"
        );
    }

    #[test]
    fn powershell_scripts_quote_paths_safely() {
        assert_eq!(powershell_literal("C:\\a'b").unwrap(), "'C:\\a''b'");
        assert!(powershell_literal("a\nb").is_err());
        assert!(powershell_literal("").is_err());

        let path = Path::new("C:\\Users\\o'neil\\pkg.Msix");
        let install = add_appx_script(path).unwrap();
        assert!(install.contains("'C:\\Users\\o''neil\\pkg.Msix'"));
        assert!(install.contains("Add-AppxPackage @arguments"));
        assert!(install.contains("INSTALL_LOCATION="));
        let signature = authenticode_script(path).unwrap();
        assert!(
            signature
                .contains("Get-AuthenticodeSignature -LiteralPath 'C:\\Users\\o''neil\\pkg.Msix'")
        );
    }

    #[test]
    fn reads_install_location_marker() {
        assert_eq!(
            parse_install_location(
                "noise\r\nINSTALL_LOCATION=C:\\Program Files\\WindowsApps\\OpenAI.Codex\r\n"
            )
            .as_deref(),
            Some("C:\\Program Files\\WindowsApps\\OpenAI.Codex")
        );
        assert_eq!(parse_install_location("INSTALL_LOCATION=\n"), None);
    }
}
