//! Runtime printf-style formatting for the C → Rust error bridge.
//!
//! [`format_message`] is a narrow re-implementation of `vsnprintf` covering exactly the
//! conversion specifiers used by pgBackRust's `THROW_FMT` / `errorInternalThrowFmt` call
//! sites (verified by grep across `src/`):
//!
//! - `%s`, `%c`, `%d` / `%i`, `%u`, `%X`, `%%`
//! - length modifiers `z` (`size_t` / `ssize_t`) and `l` (`long` / `unsigned long`)
//! - flags `0` and width digits — `%02d`, `%03u`, `%04d`, `%02X`
//! - precision on strings — `%.3s`, `%.16s`
//!
//! Any other specifier is treated as a programmer error: the function emits the literal
//! `%c` token (so the corruption is visible in tests) and a debug assertion fires. We
//! deliberately do **not** support `%n`, `%p`, floating-point conversions, `%h*`, or
//! width with `*` — none of those appear in `THROW_FMT` sites today and adding them
//! would mean carrying ABI baggage no caller exercises.
//!
//! C `va_arg` cannot cross the FFI boundary directly, so the public entry point takes a
//! pre-marshalled `&[Arg]` slice. The C side walks the format string, reads each
//! `va_arg` according to the spec, and packs the results into the typed blob exposed
//! through `pgbr-ffi::PgbrFmtArg`.

/// Typed printf argument crossing the FFI boundary.
///
/// The lifetime parameter on [`Arg::Str`] tracks the C-owned buffer; the C caller
/// guarantees it remains valid for the duration of the [`format_message`] call.
#[derive(Debug, Clone, Copy)]
pub enum Arg<'a> {
    /// 32-bit signed integer (matches C `int`).
    I32(i32),
    /// 32-bit unsigned integer (matches C `unsigned int`).
    U32(u32),
    /// 64-bit signed integer (matches C `long` on LP64 platforms).
    I64(i64),
    /// 64-bit unsigned integer (matches C `unsigned long` on LP64 platforms).
    U64(u64),
    /// Signed pointer-width integer (matches C `ssize_t`).
    Isize(isize),
    /// Unsigned pointer-width integer (matches C `size_t`).
    Usize(usize),
    /// Single byte interpreted as a character (matches the `int` promotion of C `char`).
    Char(u8),
    /// UTF-8 string slice borrowed from the caller for the duration of the call.
    Str(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LenMod {
    None,
    Z,
    L,
    LL,
}

#[derive(Debug, Clone, Copy)]
struct Spec {
    zero_pad: bool,
    width: Option<u32>,
    precision: Option<u32>,
    length: LenMod,
}

/// Render `template` with `args` substituted in printf order.
///
/// The result is allocated freshly; callers that need a fixed-size destination buffer
/// can copy from the returned `String`. See the module docs for the supported spec set.
#[must_use]
pub fn format_message(template: &str, args: &[Arg<'_>]) -> String {
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len() + 32);
    let mut i = 0_usize;
    let mut span_start = 0_usize;
    let mut next_arg = 0_usize;

    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        // Flush text accumulated before this `%`.
        out.push_str(&template[span_start..i]);
        i += 1; // consume the `%`

        let (spec, conv_byte, new_i) = parse_spec(bytes, i);
        i = new_i;
        span_start = i;
        let Some(conv) = conv_byte else {
            // Dangling `%` at end of template — emit it literally.
            out.push('%');
            continue;
        };

        match conv {
            b'%' => out.push('%'),
            b's' => {
                emit_str(&mut out, args.get(next_arg).copied(), spec.precision);
                next_arg += 1;
            }
            b'c' => {
                emit_char(&mut out, args.get(next_arg).copied());
                next_arg += 1;
            }
            b'd' | b'i' => {
                emit_signed(&mut out, args.get(next_arg).copied(), spec);
                next_arg += 1;
            }
            b'u' => {
                emit_unsigned(&mut out, args.get(next_arg).copied(), spec, false);
                next_arg += 1;
            }
            b'X' => {
                emit_unsigned(&mut out, args.get(next_arg).copied(), spec, true);
                next_arg += 1;
            }
            other => {
                // Reachable only if a caller adds a new specifier without updating us;
                // surface it loudly under cfg(debug_assertions) and emit the literal token
                // so production traces can still flag the corruption.
                debug_assert!(false, "format_message: unsupported printf specifier `%{}`", other as char);
                out.push('%');
                out.push(other as char);
            }
        }
    }

    out.push_str(&template[span_start..]);
    out
}

fn parse_spec(bytes: &[u8], start: usize) -> (Spec, Option<u8>, usize) {
    let mut spec = Spec {
        zero_pad: false,
        width: None,
        precision: None,
        length: LenMod::None,
    };
    let mut i = start;

    if bytes.get(i).copied() == Some(b'0') {
        spec.zero_pad = true;
        i += 1;
    }
    while let Some(&b) = bytes.get(i) {
        if !b.is_ascii_digit() {
            break;
        }
        spec.width = Some(spec.width.unwrap_or(0) * 10 + u32::from(b - b'0'));
        i += 1;
    }
    if bytes.get(i).copied() == Some(b'.') {
        i += 1;
        let mut p = 0_u32;
        while let Some(&b) = bytes.get(i) {
            if !b.is_ascii_digit() {
                break;
            }
            p = p * 10 + u32::from(b - b'0');
            i += 1;
        }
        spec.precision = Some(p);
    }
    match bytes.get(i).copied() {
        Some(b'z') => {
            spec.length = LenMod::Z;
            i += 1;
        }
        Some(b'l') => {
            i += 1;
            if bytes.get(i).copied() == Some(b'l') {
                spec.length = LenMod::LL;
                i += 1;
            } else {
                spec.length = LenMod::L;
            }
        }
        _ => {}
    }
    let conv = bytes.get(i).copied();
    if conv.is_some() {
        i += 1;
    }
    (spec, conv, i)
}

fn emit_str(out: &mut String, arg: Option<Arg<'_>>, precision: Option<u32>) {
    let s = match arg {
        Some(Arg::Str(s)) => s,
        _ => "",
    };
    // Char-boundary safe truncation: walk char_indices to the p-th char.
    let truncated = precision.map_or(s, |p| s.char_indices().nth(p as usize).map_or(s, |(idx, _)| &s[..idx]));
    out.push_str(truncated);
}

fn emit_char(out: &mut String, arg: Option<Arg<'_>>) {
    if let Some(Arg::Char(b)) = arg {
        out.push(b as char);
    }
}

fn emit_signed(out: &mut String, arg: Option<Arg<'_>>, spec: Spec) {
    let v: i64 = match (arg, spec.length) {
        (Some(Arg::I32(v)), LenMod::None) => i64::from(v),
        (Some(Arg::Isize(v)), LenMod::Z) => v as i64,
        (Some(Arg::I64(v)), LenMod::L | LenMod::LL) => v,
        _ => 0,
    };
    let body = v.to_string();
    pad_into(out, &body, spec.zero_pad, spec.width, v < 0);
}

fn emit_unsigned(out: &mut String, arg: Option<Arg<'_>>, spec: Spec, hex_upper: bool) {
    let v: u64 = match (arg, spec.length) {
        (Some(Arg::U32(v)), LenMod::None) => u64::from(v),
        (Some(Arg::Usize(v)), LenMod::Z) => v as u64,
        (Some(Arg::U64(v)), LenMod::L | LenMod::LL) => v,
        // Hex specifier is most often given an `int` arg from the C side; accept it.
        (Some(Arg::I32(v)), LenMod::None) => u64::from(v.cast_unsigned()),
        _ => 0,
    };
    let body = if hex_upper { format!("{v:X}") } else { v.to_string() };
    pad_into(out, &body, spec.zero_pad, spec.width, false);
}

fn pad_into(out: &mut String, body: &str, zero_pad: bool, width: Option<u32>, body_has_sign: bool) {
    let Some(w) = width else {
        out.push_str(body);
        return;
    };
    let w = w as usize;
    if body.len() >= w {
        out.push_str(body);
        return;
    }
    let pad_count = w - body.len();
    if zero_pad && body_has_sign {
        // printf rule: "%05d" with -7 produces "-0007" (sign first, then zero-pad).
        out.push('-');
        for _ in 0..pad_count {
            out.push('0');
        }
        out.push_str(&body[1..]);
    } else if zero_pad {
        for _ in 0..pad_count {
            out.push('0');
        }
        out.push_str(body);
    } else {
        for _ in 0..pad_count {
            out.push(' ');
        }
        out.push_str(body);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn literal_template_passes_through() {
        assert_eq!(format_message("hello", &[]), "hello");
        assert_eq!(format_message("", &[]), "");
        assert_eq!(format_message("path /etc/foo bar", &[]), "path /etc/foo bar");
    }

    #[test]
    fn percent_percent_emits_literal_percent() {
        assert_eq!(format_message("%%", &[]), "%");
        assert_eq!(format_message("100%% done", &[]), "100% done");
    }

    #[test]
    fn percent_s_substitutes_string() {
        assert_eq!(format_message("hi %s", &[Arg::Str("world")]), "hi world");
        assert_eq!(format_message("[%s]", &[Arg::Str("")]), "[]");
    }

    #[test]
    fn percent_s_with_precision_truncates() {
        assert_eq!(format_message("%.3s", &[Arg::Str("abcdef")]), "abc");
        assert_eq!(format_message("%.16s", &[Arg::Str("short")]), "short");
        assert_eq!(format_message("%.0s", &[Arg::Str("abc")]), "");
    }

    #[test]
    fn percent_d_signed_int() {
        assert_eq!(format_message("%d", &[Arg::I32(42)]), "42");
        assert_eq!(format_message("%d", &[Arg::I32(-7)]), "-7");
        assert_eq!(format_message("%02d", &[Arg::I32(5)]), "05");
        assert_eq!(format_message("%04d", &[Arg::I32(7)]), "0007");
        assert_eq!(format_message("%05d", &[Arg::I32(-7)]), "-0007");
    }

    #[test]
    fn percent_u_unsigned_int() {
        assert_eq!(format_message("%u", &[Arg::U32(42)]), "42");
        assert_eq!(format_message("%02u", &[Arg::U32(5)]), "05");
        assert_eq!(format_message("%03u", &[Arg::U32(12)]), "012");
    }

    #[test]
    fn percent_zu_size_t() {
        assert_eq!(format_message("%zu", &[Arg::Usize(8192)]), "8192");
        assert_eq!(format_message("%zd", &[Arg::Isize(-1)]), "-1");
    }

    #[test]
    fn percent_lu_long() {
        assert_eq!(format_message("%lu", &[Arg::U64(12_345_678_900)]), "12345678900");
    }

    #[test]
    fn percent_x_uppercase_hex() {
        assert_eq!(format_message("%X", &[Arg::U32(0xABC)]), "ABC");
        assert_eq!(format_message("%02X", &[Arg::U32(0x0F)]), "0F");
        assert_eq!(format_message("%02X", &[Arg::U32(0xFF)]), "FF");
        assert_eq!(format_message("%02X", &[Arg::U32(0x123)]), "123");
    }

    #[test]
    fn percent_c_byte() {
        assert_eq!(format_message("%c", &[Arg::Char(b'A')]), "A");
        assert_eq!(format_message("[%c]", &[Arg::Char(b'?')]), "[?]");
    }

    #[test]
    fn multiple_specifiers_match_argument_order() {
        let args = [Arg::Str("foo"), Arg::I32(42), Arg::U32(7)];
        assert_eq!(format_message("%s/%d/%u", &args), "foo/42/7");
    }

    #[test]
    fn realistic_pgbr_throw_messages() {
        // From src/common/compress/gz/common.c via THROWP_FMT in the gzError shim.
        let msg = format_message("zlib threw error: [%d] %s", &[Arg::I32(-3), Arg::Str("data error")]);
        assert_eq!(msg, "zlib threw error: [-3] data error");

        // From the lock acquire path, illustrative.
        let msg = format_message(
            "unable to acquire lock on file '%s': %d",
            &[Arg::Str("/var/run/x.lock"), Arg::I32(11)],
        );
        assert_eq!(msg, "unable to acquire lock on file '/var/run/x.lock': 11");

        // %02X bytes — used by hash printing.
        let msg = format_message("%02X%02X", &[Arg::U32(0x0A), Arg::U32(0xFF)]);
        assert_eq!(msg, "0AFF");
    }

    #[test]
    fn dangling_percent_emits_literal() {
        assert_eq!(format_message("oops %", &[]), "oops %");
    }

    #[test]
    fn precision_respects_char_boundaries() {
        // 4-byte UTF-8 char (🦀) followed by ASCII; precision 1 keeps just the crab.
        assert_eq!(format_message("%.1s", &[Arg::Str("🦀ab")]), "🦀");
        assert_eq!(format_message("%.2s", &[Arg::Str("🦀ab")]), "🦀a");
    }

    #[test]
    fn missing_argument_renders_as_default() {
        // C printf is undefined for missing args; we substitute zero/empty rather than
        // crash, so a malformed call site at least produces a parseable message.
        assert_eq!(format_message("%s/%d", &[]), "/0");
    }
}
