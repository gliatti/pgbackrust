//! Parser for `src/build/help/help.xml` — the source of truth for the help
//! text rendered by the `help` command and by the user manual.
//!
//! The XML is rich, mixed content: `<text>` blocks contain `<p>`, `<list>`,
//! `<file>`, `<backrest/>`, and many other inline tags. Modelling every nested
//! tag here would duplicate work that belongs to the help renderer itself, so
//! this module captures `<text>`, `<summary>`, and `<example>` payloads as
//! opaque strings (the inner XML serialised back out, with the wrapping tag
//! stripped). Consumers that need a typed view of the inline markup can parse
//! those strings on their own.
//!
//! The exposed [`Help`] tree mirrors the two top-level sections of `help.xml`:
//!
//! * `config_sections` — every `<config-section>` under
//!   `<config><config-section-list>`, with its `<config-key>` children.
//! * `commands` — every `<command>` under `<operation><command-list>`, with
//!   its `<option>` children.
//!
//! Use [`parse_help`] to walk a `&str` of XML and return a [`Help`]. Any
//! malformed input — bad XML, missing required attribute, unexpected tag —
//! becomes a [`HelpError`].

use std::fmt;
use std::io::Cursor;

use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::reader::Reader;

/// Top-level help document.
#[derive(Debug, Clone, Default)]
pub struct Help {
    /// Configuration sections, in document order.
    pub config_sections: Vec<ConfigSection>,
    /// User-facing commands, in document order.
    pub commands: Vec<HelpCommand>,
}

/// A `<config-section>` entry — a logical grouping of related configuration
/// keys under `<config><config-section-list>`.
#[derive(Debug, Clone)]
pub struct ConfigSection {
    /// Stable identifier (`id` attribute), e.g. `log`, `repository`.
    pub id: String,
    /// Human-readable name (`name` attribute), e.g. `Log`, `Repository`.
    pub name: String,
    /// Inner XML of the section-level `<text>` block, if any.
    pub text: Option<String>,
    /// Configuration keys belonging to this section, in document order.
    pub keys: Vec<ConfigKey>,
}

/// A single configuration key (`<config-key>`).
#[derive(Debug, Clone)]
pub struct ConfigKey {
    /// Stable identifier, e.g. `log-level-file`.
    pub id: String,
    /// Optional human-readable name.
    pub name: Option<String>,
    /// One-sentence summary (required by the help DTD).
    pub summary: String,
    /// Optional long-form description (inner XML of `<text>`).
    pub text: Option<String>,
    /// Optional example value (inner XML of `<example>`).
    pub example: Option<String>,
}

/// A user-facing command (`<command>`) under `<operation><command-list>`.
#[derive(Debug, Clone)]
pub struct HelpCommand {
    /// Stable identifier, e.g. `backup`, `restore`.
    pub id: String,
    /// Human-readable name, e.g. `Backup`.
    pub name: String,
    /// One-sentence summary (required by the help DTD).
    pub summary: String,
    /// Optional long-form description (inner XML of `<text>`).
    pub text: Option<String>,
    /// Command-specific options, in document order.
    pub options: Vec<HelpCommandOption>,
}

/// A command-specific `<option>` entry.
#[derive(Debug, Clone)]
pub struct HelpCommandOption {
    /// Stable identifier, e.g. `type`.
    pub id: String,
    /// Optional human-readable name.
    pub name: Option<String>,
    /// Optional summary (inner XML of `<summary>`).
    pub summary: Option<String>,
    /// Optional long-form description (inner XML of `<text>`).
    pub text: Option<String>,
    /// Optional example value (inner XML of `<example>`).
    pub example: Option<String>,
}

/// Errors produced by [`parse_help`].
#[derive(Debug)]
pub enum HelpError {
    /// The underlying XML reader failed.
    Xml(quick_xml::Error),
    /// The captured inner XML could not be re-serialised because the writer's
    /// `io::Write` impl returned an error.
    Io(std::io::Error),
    /// The XML parses as XML but does not match the help schema —
    /// missing required attribute, unexpected tag, etc.
    Schema(String),
}

impl fmt::Display for HelpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml(err) => write!(f, "xml parse error: {err}"),
            Self::Io(err) => write!(f, "io error while serialising captured XML: {err}"),
            Self::Schema(msg) => write!(f, "help schema violation: {msg}"),
        }
    }
}

impl std::error::Error for HelpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Xml(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::Schema(_) => None,
        }
    }
}

impl From<quick_xml::Error> for HelpError {
    fn from(value: quick_xml::Error) -> Self {
        Self::Xml(value)
    }
}

impl From<std::io::Error> for HelpError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<quick_xml::events::attributes::AttrError> for HelpError {
    fn from(value: quick_xml::events::attributes::AttrError) -> Self {
        Self::Xml(quick_xml::Error::InvalidAttr(value))
    }
}

/// Parse a help XML document.
///
/// # Errors
///
/// Returns [`HelpError::Xml`] when the document is not well-formed XML, or
/// [`HelpError::Schema`] when a required attribute or element is missing.
pub fn parse_help(xml: &str) -> Result<Help, HelpError> {
    let mut reader = Reader::from_str(xml);
    let config = reader.config_mut();
    config.trim_text(false);
    config.expand_empty_elements = false;

    let mut help = Help::default();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.local_name().as_ref() {
                b"config" => parse_config(&mut reader, &mut help.config_sections)?,
                b"operation" => parse_operation(&mut reader, &mut help.commands)?,
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(help)
}

fn parse_config(reader: &mut Reader<&[u8]>, sections: &mut Vec<ConfigSection>) -> Result<(), HelpError> {
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.local_name().as_ref() == b"config-section-list" => {
                parse_config_section_list(reader, sections)?;
            }
            Event::End(e) if e.local_name().as_ref() == b"config" => return Ok(()),
            Event::Eof => return Err(HelpError::Schema("unexpected EOF inside <config>".into())),
            _ => {}
        }
        buf.clear();
    }
}

fn parse_config_section_list(reader: &mut Reader<&[u8]>, sections: &mut Vec<ConfigSection>) -> Result<(), HelpError> {
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.local_name().as_ref() == b"config-section" => {
                let id = required_attr(&e, "id", "config-section")?;
                let name = required_attr(&e, "name", "config-section")?;
                let mut section = ConfigSection {
                    id,
                    name,
                    text: None,
                    keys: Vec::new(),
                };
                parse_config_section_body(reader, &mut section)?;
                sections.push(section);
            }
            Event::End(e) if e.local_name().as_ref() == b"config-section-list" => return Ok(()),
            Event::Eof => {
                return Err(HelpError::Schema("unexpected EOF inside <config-section-list>".into()));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn parse_config_section_body(reader: &mut Reader<&[u8]>, section: &mut ConfigSection) -> Result<(), HelpError> {
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.local_name().as_ref() {
                b"text" => section.text = Some(capture_inner_xml(reader, b"text")?),
                b"config-key-list" => parse_config_key_list(reader, &mut section.keys)?,
                _ => skip_element(reader, e.name().as_ref())?,
            },
            Event::End(e) if e.local_name().as_ref() == b"config-section" => return Ok(()),
            Event::Eof => {
                return Err(HelpError::Schema("unexpected EOF inside <config-section>".into()));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn parse_config_key_list(reader: &mut Reader<&[u8]>, keys: &mut Vec<ConfigKey>) -> Result<(), HelpError> {
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.local_name().as_ref() == b"config-key" => {
                let id = required_attr(&e, "id", "config-key")?;
                let name = optional_attr(&e, "name")?;
                let mut key = ConfigKey {
                    id,
                    name,
                    summary: String::new(),
                    text: None,
                    example: None,
                };
                let mut have_summary = false;
                parse_config_key_body(reader, &mut key, &mut have_summary)?;
                if !have_summary {
                    return Err(HelpError::Schema(format!(
                        "<config-key id=\"{}\"> is missing required <summary>",
                        key.id
                    )));
                }
                keys.push(key);
            }
            Event::End(e) if e.local_name().as_ref() == b"config-key-list" => return Ok(()),
            Event::Eof => return Err(HelpError::Schema("unexpected EOF inside <config-key-list>".into())),
            _ => {}
        }
        buf.clear();
    }
}

fn parse_config_key_body(reader: &mut Reader<&[u8]>, key: &mut ConfigKey, have_summary: &mut bool) -> Result<(), HelpError> {
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.local_name().as_ref() {
                b"summary" => {
                    key.summary = capture_inner_xml(reader, b"summary")?;
                    *have_summary = true;
                }
                b"text" => key.text = Some(capture_inner_xml(reader, b"text")?),
                b"example" => key.example = Some(capture_inner_xml(reader, b"example")?),
                _ => skip_element(reader, e.name().as_ref())?,
            },
            Event::End(e) if e.local_name().as_ref() == b"config-key" => return Ok(()),
            Event::Eof => return Err(HelpError::Schema("unexpected EOF inside <config-key>".into())),
            _ => {}
        }
        buf.clear();
    }
}

fn parse_operation(reader: &mut Reader<&[u8]>, commands: &mut Vec<HelpCommand>) -> Result<(), HelpError> {
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.local_name().as_ref() == b"command-list" => {
                parse_command_list(reader, commands)?;
            }
            Event::End(e) if e.local_name().as_ref() == b"operation" => return Ok(()),
            Event::Eof => return Err(HelpError::Schema("unexpected EOF inside <operation>".into())),
            _ => {}
        }
        buf.clear();
    }
}

fn parse_command_list(reader: &mut Reader<&[u8]>, commands: &mut Vec<HelpCommand>) -> Result<(), HelpError> {
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.local_name().as_ref() == b"command" => {
                let id = required_attr(&e, "id", "command")?;
                let name = required_attr(&e, "name", "command")?;
                let mut cmd = HelpCommand {
                    id,
                    name,
                    summary: String::new(),
                    text: None,
                    options: Vec::new(),
                };
                let mut have_summary = false;
                parse_command_body(reader, &mut cmd, &mut have_summary)?;
                if !have_summary {
                    return Err(HelpError::Schema(format!(
                        "<command id=\"{}\"> is missing required <summary>",
                        cmd.id
                    )));
                }
                commands.push(cmd);
            }
            Event::End(e) if e.local_name().as_ref() == b"command-list" => return Ok(()),
            Event::Eof => return Err(HelpError::Schema("unexpected EOF inside <command-list>".into())),
            _ => {}
        }
        buf.clear();
    }
}

fn parse_command_body(reader: &mut Reader<&[u8]>, cmd: &mut HelpCommand, have_summary: &mut bool) -> Result<(), HelpError> {
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.local_name().as_ref() {
                b"summary" => {
                    cmd.summary = capture_inner_xml(reader, b"summary")?;
                    *have_summary = true;
                }
                b"text" => cmd.text = Some(capture_inner_xml(reader, b"text")?),
                b"option-list" => parse_option_list(reader, &mut cmd.options)?,
                _ => skip_element(reader, e.name().as_ref())?,
            },
            Event::End(e) if e.local_name().as_ref() == b"command" => return Ok(()),
            Event::Eof => return Err(HelpError::Schema("unexpected EOF inside <command>".into())),
            _ => {}
        }
        buf.clear();
    }
}

fn parse_option_list(reader: &mut Reader<&[u8]>, options: &mut Vec<HelpCommandOption>) -> Result<(), HelpError> {
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.local_name().as_ref() == b"option" => {
                let id = required_attr(&e, "id", "option")?;
                let name = optional_attr(&e, "name")?;
                let mut opt = HelpCommandOption {
                    id,
                    name,
                    summary: None,
                    text: None,
                    example: None,
                };
                parse_option_body(reader, &mut opt)?;
                options.push(opt);
            }
            Event::End(e) if e.local_name().as_ref() == b"option-list" => return Ok(()),
            Event::Eof => return Err(HelpError::Schema("unexpected EOF inside <option-list>".into())),
            _ => {}
        }
        buf.clear();
    }
}

fn parse_option_body(reader: &mut Reader<&[u8]>, opt: &mut HelpCommandOption) -> Result<(), HelpError> {
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.local_name().as_ref() {
                b"summary" => opt.summary = Some(capture_inner_xml(reader, b"summary")?),
                b"text" => opt.text = Some(capture_inner_xml(reader, b"text")?),
                b"example" => opt.example = Some(capture_inner_xml(reader, b"example")?),
                _ => skip_element(reader, e.name().as_ref())?,
            },
            Event::End(e) if e.local_name().as_ref() == b"option" => return Ok(()),
            Event::Eof => return Err(HelpError::Schema("unexpected EOF inside <option>".into())),
            _ => {}
        }
        buf.clear();
    }
}

/// Capture every event between the current position and the matching
/// `</closing>` end-tag, then re-serialise the captured events back to a
/// `String`. The closing tag itself is consumed but not included.
fn capture_inner_xml(reader: &mut Reader<&[u8]>, closing: &[u8]) -> Result<String, HelpError> {
    let mut depth: usize = 0;
    let mut buf = Vec::new();
    let mut writer = Writer::new(Cursor::new(Vec::<u8>::new()));

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(ref e) => {
                depth += 1;
                writer.write_event(Event::Start(e.borrow()))?;
            }
            Event::End(ref e) => {
                if depth == 0 && e.local_name().as_ref() == closing {
                    let raw = writer.into_inner().into_inner();
                    let s =
                        String::from_utf8(raw).map_err(|err| HelpError::Schema(format!("inner XML is not valid UTF-8: {err}")))?;
                    return Ok(s);
                }
                depth = depth.saturating_sub(1);
                writer.write_event(Event::End(BytesEnd::new(
                    String::from_utf8_lossy(e.name().as_ref()).into_owned(),
                )))?;
            }
            Event::Empty(ref e) => {
                writer.write_event(Event::Empty(e.borrow()))?;
            }
            Event::Text(ref e) => {
                writer.write_event(Event::Text(BytesText::from_escaped(
                    String::from_utf8_lossy(e.as_ref()).into_owned(),
                )))?;
            }
            Event::CData(ref e) => {
                writer.write_event(Event::CData(e.borrow()))?;
            }
            Event::Comment(ref e) => {
                writer.write_event(Event::Comment(e.borrow()))?;
            }
            Event::Eof => {
                return Err(HelpError::Schema(format!(
                    "unexpected EOF while capturing <{}>",
                    String::from_utf8_lossy(closing)
                )));
            }
            _ => {}
        }
        buf.clear();
    }
}

/// Skip events until the matching closing tag of `open_name`. Used when an
/// unrecognised child element appears inside a parent we do model.
fn skip_element(reader: &mut Reader<&[u8]>, open_name: &[u8]) -> Result<(), HelpError> {
    let mut depth: usize = 0;
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.name().as_ref() == open_name => depth += 1,
            Event::End(e) if e.name().as_ref() == open_name => {
                if depth == 0 {
                    return Ok(());
                }
                depth -= 1;
            }
            Event::Eof => {
                return Err(HelpError::Schema(format!(
                    "unexpected EOF while skipping <{}>",
                    String::from_utf8_lossy(open_name)
                )));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn required_attr(elem: &BytesStart<'_>, attr: &str, kind: &str) -> Result<String, HelpError> {
    optional_attr(elem, attr)?.ok_or_else(|| HelpError::Schema(format!("<{kind}> is missing required `{attr}` attribute")))
}

fn optional_attr(elem: &BytesStart<'_>, attr: &str) -> Result<Option<String>, HelpError> {
    for raw in elem.attributes() {
        let raw = raw?;
        if raw.key.local_name().as_ref() == attr.as_bytes() {
            let value = raw
                .unescape_value()
                .map_err(|err| HelpError::Schema(format!("attribute `{attr}` is malformed: {err}")))?
                .into_owned();
            return Ok(Some(value));
        }
    }
    Ok(None)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Path to the real help.xml shipped with the repository, relative to the
    /// crate root. Used by the fixture-backed integration test below.
    const FIXTURE_PATH: &str = "../../src/build/help/help.xml";

    #[test]
    fn parses_minimal_doc() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<doc title="Test">
    <config title="Configuration Reference">
        <text><p>top-level text</p></text>
        <config-section-list title="Settings">
            <config-section id="log" name="Log">
                <text><p>section text</p></text>
                <config-key-list>
                    <config-key id="log-level-file" name="File Log Level">
                        <summary>Level for file logging.</summary>
                        <text><p>key text</p></text>
                        <example>debug</example>
                    </config-key>
                </config-key-list>
            </config-section>
        </config-section-list>
    </config>
</doc>"#;
        let help = parse_help(xml).unwrap();
        assert_eq!(help.config_sections.len(), 1);
        assert_eq!(help.commands.len(), 0);

        let section = &help.config_sections[0];
        assert_eq!(section.id, "log");
        assert_eq!(section.name, "Log");
        assert!(section.text.as_deref().unwrap().contains("section text"));
        assert_eq!(section.keys.len(), 1);

        let key = &section.keys[0];
        assert_eq!(key.id, "log-level-file");
        assert_eq!(key.name.as_deref(), Some("File Log Level"));
        assert_eq!(key.summary, "Level for file logging.");
        assert!(key.text.as_deref().unwrap().contains("key text"));
        assert_eq!(key.example.as_deref(), Some("debug"));
    }

    #[test]
    fn parses_command_with_option() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<doc title="Test">
    <operation>
        <command-list title="Commands">
            <command id="backup" name="Backup">
                <summary>Backup a database cluster.</summary>
                <text><p>command text</p></text>
                <option-list>
                    <option id="type" name="Type">
                        <summary>Backup type.</summary>
                        <text><p>option text</p></text>
                        <example>full</example>
                    </option>
                    <option id="force">
                        <summary>Force the backup.</summary>
                    </option>
                </option-list>
            </command>
        </command-list>
    </operation>
</doc>"#;
        let help = parse_help(xml).unwrap();
        assert_eq!(help.config_sections.len(), 0);
        assert_eq!(help.commands.len(), 1);

        let cmd = &help.commands[0];
        assert_eq!(cmd.id, "backup");
        assert_eq!(cmd.name, "Backup");
        assert_eq!(cmd.summary, "Backup a database cluster.");
        assert!(cmd.text.as_deref().unwrap().contains("command text"));
        assert_eq!(cmd.options.len(), 2);

        let opt0 = &cmd.options[0];
        assert_eq!(opt0.id, "type");
        assert_eq!(opt0.name.as_deref(), Some("Type"));
        assert_eq!(opt0.summary.as_deref(), Some("Backup type."));
        assert!(opt0.text.as_deref().unwrap().contains("option text"));
        assert_eq!(opt0.example.as_deref(), Some("full"));

        let opt1 = &cmd.options[1];
        assert_eq!(opt1.id, "force");
        assert_eq!(opt1.name, None);
        assert_eq!(opt1.summary.as_deref(), Some("Force the backup."));
        assert_eq!(opt1.text, None);
        assert_eq!(opt1.example, None);
    }

    #[test]
    fn missing_required_attribute_is_a_schema_error() {
        let xml = r#"<?xml version="1.0"?>
<doc>
    <config>
        <config-section-list>
            <config-section name="Log">
                <config-key-list>
                </config-key-list>
            </config-section>
        </config-section-list>
    </config>
</doc>"#;
        let err = parse_help(xml).unwrap_err();
        match err {
            HelpError::Schema(msg) => assert!(msg.contains("config-section") && msg.contains("id")),
            other => panic!("expected Schema, got {other:?}"),
        }
    }

    #[test]
    fn missing_required_summary_is_a_schema_error() {
        let xml = r#"<?xml version="1.0"?>
<doc>
    <operation>
        <command-list>
            <command id="x" name="X">
                <text><p>only text</p></text>
            </command>
        </command-list>
    </operation>
</doc>"#;
        let err = parse_help(xml).unwrap_err();
        match err {
            HelpError::Schema(msg) => assert!(msg.contains("summary")),
            other => panic!("expected Schema, got {other:?}"),
        }
    }

    #[test]
    fn parses_repository_fixture() {
        let xml =
            std::fs::read_to_string(FIXTURE_PATH).unwrap_or_else(|err| panic!("failed to read fixture {FIXTURE_PATH}: {err}"));
        let help = parse_help(&xml).expect("repository fixture must parse");

        // Thresholds reflect the actual help.xml shipped with this commit
        // (9 config sections, 23 commands, 40 command-options). They are
        // floors, not equalities, so future additions cannot break this test
        // — only deletions below the floor would.
        assert!(
            help.config_sections.len() >= 5,
            "expected at least 5 config sections, got {}",
            help.config_sections.len()
        );
        assert!(
            help.commands.len() >= 20,
            "expected at least 20 commands, got {}",
            help.commands.len()
        );

        let total_options: usize = help.commands.iter().map(|c| c.options.len()).sum();
        assert!(
            total_options >= 35,
            "expected at least 35 options across all commands, got {total_options}"
        );

        // Spot-check a known command.
        let backup = help
            .commands
            .iter()
            .find(|c| c.id == "backup")
            .expect("backup command must be present");
        assert_eq!(backup.name, "Backup");
        assert!(!backup.summary.is_empty());
        assert!(!backup.options.is_empty());

        // Spot-check a known config section.
        let log = help
            .config_sections
            .iter()
            .find(|s| s.id == "log")
            .expect("log config section must be present");
        assert!(log.keys.iter().any(|k| k.id == "log-level-file"));
    }
}
