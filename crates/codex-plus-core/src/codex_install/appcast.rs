//! Sparkle appcast 解析：只取首次安装需要的字段（版本、完整包地址 / 大小 / 签名、系统要求）。
//!
//! 元素和属性按本地名匹配，忽略 `sparkle:` 前缀，兼容不同的命名空间写法；
//! `<sparkle:deltas>` 里的增量包对首次安装没有用，直接跳过。

use anyhow::{Context, bail};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppcastItem {
    /// `sparkle:version`：单调递增的构建号，用来挑最新版。
    pub(crate) build: u64,
    /// `sparkle:shortVersionString`：展示给用户的版本号。
    pub(crate) short_version: String,
    pub(crate) minimum_system_version: Option<String>,
    pub(crate) hardware_requirements: Option<String>,
    /// 完整安装包（`.zip`）。
    pub(crate) url: String,
    pub(crate) length: u64,
    pub(crate) ed_signature: String,
}

#[derive(Default)]
struct PartialItem {
    build: Option<u64>,
    short_version: Option<String>,
    minimum_system_version: Option<String>,
    hardware_requirements: Option<String>,
    enclosure: Option<Enclosure>,
}

#[derive(Default)]
struct Enclosure {
    url: String,
    length: u64,
    ed_signature: Option<String>,
    build: Option<u64>,
    short_version: Option<String>,
}

#[derive(Clone, Copy)]
enum TextField {
    Build,
    ShortVersion,
    MinimumSystemVersion,
    HardwareRequirements,
}

impl PartialItem {
    fn set(&mut self, field: TextField, value: &str) {
        if value.is_empty() {
            return;
        }
        match field {
            TextField::Build => self.build = value.parse().ok(),
            TextField::ShortVersion => self.short_version = Some(value.to_string()),
            TextField::MinimumSystemVersion => {
                self.minimum_system_version = Some(value.to_string())
            }
            TextField::HardwareRequirements => self.hardware_requirements = Some(value.to_string()),
        }
    }

    /// 没有完整包、没有签名或读不出构建号的条目一律丢弃：没有签名就无从校验。
    fn finish(self) -> Option<AppcastItem> {
        let enclosure = self.enclosure?;
        let ed_signature = enclosure.ed_signature?;
        let build = self.build.or(enclosure.build)?;
        if enclosure.url.is_empty() {
            return None;
        }
        Some(AppcastItem {
            build,
            short_version: self
                .short_version
                .or(enclosure.short_version)
                .unwrap_or_else(|| build.to_string()),
            minimum_system_version: self.minimum_system_version,
            hardware_requirements: self.hardware_requirements,
            url: enclosure.url,
            length: enclosure.length,
            ed_signature,
        })
    }
}

fn text_field_for(local_name: &[u8]) -> Option<TextField> {
    match local_name {
        b"version" => Some(TextField::Build),
        b"shortVersionString" => Some(TextField::ShortVersion),
        b"minimumSystemVersion" => Some(TextField::MinimumSystemVersion),
        b"hardwareRequirements" => Some(TextField::HardwareRequirements),
        _ => None,
    }
}

pub(crate) fn parse_appcast(xml: &str) -> anyhow::Result<Vec<AppcastItem>> {
    let mut reader = Reader::from_str(xml);
    let mut items = Vec::new();
    let mut current: Option<PartialItem> = None;
    let mut deltas_depth = 0usize;
    let mut text_field: Option<TextField> = None;
    loop {
        match reader.read_event().context("appcast 不是合法的 XML")? {
            Event::Start(element) => {
                text_field = None;
                match element.local_name().as_ref() {
                    b"item" => current = Some(PartialItem::default()),
                    b"deltas" => deltas_depth += 1,
                    b"enclosure" => record_enclosure(&mut current, deltas_depth, &element)?,
                    name => text_field = text_field_for(name),
                }
            }
            Event::Empty(element) => {
                if element.local_name().as_ref() == b"enclosure" {
                    record_enclosure(&mut current, deltas_depth, &element)?;
                }
            }
            Event::Text(text) => {
                if let (Some(field), Some(item)) = (text_field, current.as_mut()) {
                    let value = text.decode().context("appcast 文本编码异常")?;
                    item.set(field, value.trim());
                }
            }
            Event::End(element) => {
                text_field = None;
                match element.local_name().as_ref() {
                    b"item" => {
                        if let Some(item) = current.take().and_then(PartialItem::finish) {
                            items.push(item);
                        }
                    }
                    b"deltas" => deltas_depth = deltas_depth.saturating_sub(1),
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if items.is_empty() {
        bail!("appcast 里没有可安装的版本");
    }
    Ok(items)
}

fn record_enclosure(
    current: &mut Option<PartialItem>,
    deltas_depth: usize,
    element: &BytesStart,
) -> anyhow::Result<()> {
    if deltas_depth > 0 {
        return Ok(());
    }
    let Some(item) = current.as_mut() else {
        return Ok(());
    };
    let mut enclosure = Enclosure::default();
    for attribute in element.attributes() {
        let attribute = attribute.context("appcast 安装包属性格式异常")?;
        let value = attribute
            .unescape_value()
            .context("appcast 安装包属性编码异常")?;
        let value = value.trim();
        match attribute.key.local_name().as_ref() {
            b"url" => enclosure.url = value.to_string(),
            b"length" => enclosure.length = value.parse().unwrap_or(0),
            b"edSignature" => enclosure.ed_signature = Some(value.to_string()),
            b"version" => enclosure.build = value.parse().ok(),
            b"shortVersionString" => enclosure.short_version = Some(value.to_string()),
            _ => {}
        }
    }
    item.enclosure = Some(enclosure);
    Ok(())
}

/// 构建号最大的条目即最新版。
pub(crate) fn latest(items: &[AppcastItem]) -> Option<&AppcastItem> {
    items.iter().max_by_key(|item| item.build)
}

/// `current >= minimum`，按点分数字逐段比较（`13.0` 对 `14.6.1`）。
pub(crate) fn version_at_least(current: &str, minimum: &str) -> bool {
    let parse = |value: &str| {
        value
            .trim()
            .split('.')
            .map(|part| part.trim().parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let mut current = parse(current);
    let mut minimum = parse(minimum);
    let len = current.len().max(minimum.len());
    current.resize(len, 0);
    minimum.resize(len, 0);
    current >= minimum
}

/// `sparkle:hardwareRequirements` 是否允许当前架构；没有声明时视为不限。
pub(crate) fn hardware_supported(requirements: Option<&str>, arch: &str) -> bool {
    requirements.is_none_or(|requirements| {
        let mut declared = requirements
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .peekable();
        declared.peek().is_none() || declared.any(|value| value.eq_ignore_ascii_case(arch))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // 结构取自真实的 Codex appcast（裁掉了多余条目与增量包）。
    const APPCAST: &str = r#"<?xml version='1.0' encoding='utf-8'?>
<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" version="2.0">
    <channel>
        <title>Codex</title>
        <item>
            <title>26.1007.71326</title>
            <pubDate>Wed, 14 Oct 2026 00:50:34 +0000</pubDate>
            <sparkle:version>20398</sparkle:version>
            <sparkle:shortVersionString>26.1007.71326</sparkle:shortVersionString>
            <sparkle:minimumSystemVersion>13.0</sparkle:minimumSystemVersion>
            <sparkle:hardwareRequirements>arm64</sparkle:hardwareRequirements>
            <enclosure url="https://persistent.oaistatic.com/codex-app-prod/ChatGPT-darwin-arm64-26.1007.71326.zip" length="719853822" type="application/octet-stream" sparkle:edSignature="kdzIxGPNvDt9o6obGmyIgVzsZahZSsw/rNQQgT3+LleP/RTNujHmNZVEBYB+1w9a+ILgZfpSR4qnwxNJH/NdAQ==" />
            <sparkle:deltas>
                <enclosure url="https://persistent.oaistatic.com/codex-app-prod/ChatGPT20398-20324-arm64.delta" sparkle:deltaFrom="20324" length="21100210" type="application/octet-stream" sparkle:edSignature="dGQESoIk/BSWVWYY0ZND/PZticYom2neUdSGE4QngUD12mJWq7Cqw9o0Kep7Z54tNEJ47qDfZ3aSBCPIEkmSAQ==" />
            </sparkle:deltas>
        </item>
        <item>
            <title>26.1007.30912</title>
            <sparkle:version>20324</sparkle:version>
            <sparkle:shortVersionString>26.1007.30912</sparkle:shortVersionString>
            <sparkle:minimumSystemVersion>13.0</sparkle:minimumSystemVersion>
            <enclosure url="https://persistent.oaistatic.com/codex-app-prod/ChatGPT-darwin-arm64-26.1007.30912.zip" length="719404869" type="application/octet-stream" sparkle:edSignature="NK8Q2+pYxy0zanOhiAvqpvTjSavnKrwKWocD+rcVr54f35hMCt0VFYSygUsgGXjhYKjQsbugrsbGrxNbQMr3Dw==" />
        </item>
    </channel>
</rss>"#;

    #[test]
    fn parses_full_packages_and_skips_deltas() {
        let items = parse_appcast(APPCAST).unwrap();

        assert_eq!(items.len(), 2);
        let newest = latest(&items).unwrap();
        assert_eq!(newest.build, 20398);
        assert_eq!(newest.short_version, "26.1007.71326");
        assert_eq!(newest.minimum_system_version.as_deref(), Some("13.0"));
        assert_eq!(newest.hardware_requirements.as_deref(), Some("arm64"));
        assert_eq!(
            newest.url,
            "https://persistent.oaistatic.com/codex-app-prod/ChatGPT-darwin-arm64-26.1007.71326.zip"
        );
        assert_eq!(newest.length, 719_853_822);
        assert!(newest.ed_signature.starts_with("kdzIxGPN"));
    }

    #[test]
    fn latest_picks_highest_build_regardless_of_order() {
        let items = parse_appcast(APPCAST).unwrap();
        let mut reversed = items.clone();
        reversed.reverse();

        assert_eq!(latest(&reversed).unwrap().build, 20398);
    }

    #[test]
    fn drops_items_without_signature() {
        let xml = r#"<rss><channel><item>
            <sparkle:version xmlns:sparkle="s">7</sparkle:version>
            <enclosure url="https://example.test/a.zip" length="3" />
        </item></channel></rss>"#;

        assert!(parse_appcast(xml).is_err());
    }

    #[test]
    fn reads_build_from_enclosure_attribute_when_element_is_missing() {
        let xml = r#"<rss xmlns:sparkle="s"><channel><item>
            <enclosure url="https://example.test/a.zip" length="3" sparkle:version="42" sparkle:shortVersionString="1.2" sparkle:edSignature="c2ln" />
        </item></channel></rss>"#;

        let items = parse_appcast(xml).unwrap();
        assert_eq!(items[0].build, 42);
        assert_eq!(items[0].short_version, "1.2");
    }

    #[test]
    fn rejects_malformed_xml() {
        assert!(parse_appcast("<rss><channel><item>").is_err());
        assert!(parse_appcast("not xml at all").is_err());
    }

    #[test]
    fn compares_dotted_versions_numerically() {
        assert!(version_at_least("14.6.1", "13.0"));
        assert!(version_at_least("13.0", "13"));
        assert!(version_at_least("13.10", "13.9"));
        assert!(!version_at_least("12.7.6", "13.0"));
    }

    #[test]
    fn hardware_requirements_gate_architecture() {
        assert!(hardware_supported(None, "x86_64"));
        assert!(hardware_supported(Some(""), "x86_64"));
        assert!(hardware_supported(Some("arm64"), "arm64"));
        assert!(hardware_supported(Some("x86_64, arm64"), "arm64"));
        assert!(!hardware_supported(Some("arm64"), "x86_64"));
    }
}
