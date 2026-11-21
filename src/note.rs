//! The note the phone shows with a remote approval (1..128 bytes of UTF-8):
//! what is being signed, read from the data the client asked to sign.
//!
//! - SSH user authentication (RFC 4252 section 7): `string session id`,
//!   `byte SSH_MSG_USERAUTH_REQUEST (50)`, `string user name`, ... ->
//!   "ssh login as <user>".
//! - SSH signature (OpenSSH PROTOCOL.sshsig): `byte[6] "SSHSIG"`,
//!   `string namespace`, ... -> "sign (<namespace>)", e.g. "sign (git)".
//! - Anything else -> "sign".

const NOTE_MAX: usize = 128;
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

/// `<what> · <key label> · <computer>`, cut to 128 bytes on a character boundary.
pub fn note(data: &[u8], key_label: &str, computer: Option<&str>) -> String {
    let what = match (sshsig_namespace(data), userauth_user(data)) {
        (Some(ns), _) => format!("sign ({})", printable(ns)),
        (None, Some(user)) => format!("ssh login as {}", printable(user)),
        _ => "sign".to_owned(),
    };
    let mut s = format!("{what} · {key_label}");
    if let Some(c) = computer.filter(|c| !c.is_empty()) {
        s.push_str(" · ");
        s.push_str(c);
    }
    truncate(s, NOTE_MAX)
}

/// The name of this computer, if the environment says it.
pub fn computer_name() -> Option<String> {
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).ok().filter(|s| !s.is_empty())
}

/// An SSH `string`: u32 big-endian length, then the bytes. Returns (value, rest).
fn ssh_string(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
    let v = b.get(4..4 + len)?;
    Some((v, &b[4 + len..]))
}

fn sshsig_namespace(data: &[u8]) -> Option<&[u8]> {
    let rest = data.strip_prefix(b"SSHSIG")?;
    Some(ssh_string(rest)?.0)
}

fn userauth_user(data: &[u8]) -> Option<&[u8]> {
    let (_session_id, rest) = ssh_string(data)?;
    let (&msg, rest) = rest.split_first()?;
    if msg != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    Some(ssh_string(rest)?.0)
}

/// Text for the phone: UTF-8 with control characters replaced.
fn printable(b: &[u8]) -> String {
    String::from_utf8_lossy(b).chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(v: &[u8]) -> Vec<u8> {
        let mut out = (v.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(v);
        out
    }

    #[test]
    fn userauth() {
        let mut d = string(&[0xaa; 32]);
        d.push(SSH_MSG_USERAUTH_REQUEST);
        d.extend(string(b"chris"));
        d.extend(string(b"ssh-connection"));
        assert_eq!(note(&d, "work key", Some("PC1")), "ssh login as chris · work key · PC1");
    }

    #[test]
    fn sshsig() {
        let mut d = b"SSHSIG".to_vec();
        d.extend(string(b"git"));
        d.extend(string(b""));
        assert_eq!(note(&d, "k", None), "sign (git) · k");
    }

    #[test]
    fn other_and_limits() {
        assert_eq!(note(b"\x00\x01", "k", None), "sign · k");
        let n = note(b"", &"ż".repeat(100), Some("PC"));
        assert!(n.len() <= NOTE_MAX && n.starts_with("sign · ż"));
        let mut d = string(&[1; 4]);
        d.push(SSH_MSG_USERAUTH_REQUEST);
        d.extend(string(b"a\nb"));
        assert_eq!(note(&d, "k", None), "ssh login as a?b · k");
    }
}
