//! Per-share authorization (#40): who may connect to a share, and who gets
//! it read-only.
//!
//! A `[[share]]` may carry `valid_users`, `invalid_users` and
//! `read_only_users`. Each entry names a user or, with a leading `@`, a group:
//!
//! | entry              | matches                                                    |
//! |--------------------|------------------------------------------------------------|
//! | `alice`            | the local (NTLM) `[[user]]` alice, or the Kerberos principal `alice@<[kerberos].realm>` |
//! | `alice@AD.G8.LO`   | that Kerberos principal                                    |
//! | `AD\alice`         | the user whose PAC says domain `AD`, account `alice`       |
//! | `@S-1-5-21-…-1105` | a session whose PAC carries that SID                       |
//! | `@Domain Admins`   | a well-known domain group (RID) of the user's own domain; `@AD\Domain Admins` also checks the domain |
//! | `@staff`           | the `[[group]]` named `staff`: its `sid` in the PAC, or the user in its `members` |
//!
//! Names compare case-insensitively. Group membership comes from the PAC of a
//! Kerberos ticket (`pac.rs`); the PAC has no group names, so a group is
//! named by SID, by well-known RID, or through the `[[group]]` table — there
//! is no LDAP lookup. Guest and anonymous sessions match nothing.
//!
//! Decision at TREE_CONNECT: a match in `invalid_users` denies; a non-empty
//! `valid_users` without a match denies; otherwise the tree is read-only when
//! the share is `read_only` or the user matches `read_only_users`.

use crate::config::{Config, ShareCfg};
use crate::pac::{LogonInfo, Sid};

/// Well-known domain-relative group RIDs (MS-DTYP 2.4.2.4) accepted by name.
const WELL_KNOWN: &[(&str, u32)] = &[
    ("domain admins", 512),
    ("domain users", 513),
    ("domain guests", 514),
    ("domain computers", 515),
    ("domain controllers", 516),
    ("cert publishers", 517),
    ("schema admins", 518),
    ("enterprise admins", 519),
    ("group policy creator owners", 520),
    ("read-only domain controllers", 521),
    ("cloneable domain controllers", 522),
    ("protected users", 525),
    ("key admins", 526),
    ("enterprise key admins", 527),
];

/// One parsed share-list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    User(UserPat),
    /// A SID that must appear in the PAC.
    GroupSid(Sid),
    /// A well-known RID in the user's domain (and that domain, if named).
    WellKnown { domain: Option<String>, rid: u32 },
    /// Index into `Config::groups`.
    Table(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserPat {
    /// `alice`: a local user, or `alice@<[kerberos].realm>`.
    Bare(String),
    /// `alice@REALM`: a Kerberos principal.
    Principal(String),
    /// `DOM\alice`: PAC domain + account name.
    DomUser { domain: String, name: String },
}

impl UserPat {
    pub fn parse(s: &str) -> Result<UserPat, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty user name".into());
        }
        if let Some((d, n)) = s.split_once('\\') {
            if d.is_empty() || n.is_empty() || n.contains(['\\', '@']) {
                return Err(format!("invalid DOMAIN\\user {s:?}"));
            }
            return Ok(UserPat::DomUser { domain: d.into(), name: n.into() });
        }
        match s.rsplit_once('@') {
            Some((u, r)) if !u.is_empty() && !r.is_empty() => Ok(UserPat::Principal(s.into())),
            Some(_) => Err(format!("invalid principal {s:?}")),
            None => Ok(UserPat::Bare(s.into())),
        }
    }
}

impl Entry {
    /// Parse a list entry; `@group` names resolve against `cfg.groups` first,
    /// then the well-known RIDs. An unknown group is a config error.
    pub fn parse(s: &str, cfg: &Config) -> Result<Entry, String> {
        let Some(g) = s.trim().strip_prefix('@') else {
            return UserPat::parse(s).map(Entry::User);
        };
        let g = g.trim();
        if g.len() > 2 && g[..2].eq_ignore_ascii_case("S-") {
            return Sid::parse(g).map(Entry::GroupSid).ok_or_else(|| format!("invalid SID {g:?}"));
        }
        if let Some(i) = cfg.groups.iter().position(|t| t.name.eq_ignore_ascii_case(g)) {
            return Ok(Entry::Table(i));
        }
        let (domain, name) = match g.split_once('\\') {
            Some((d, n)) if !d.is_empty() => (Some(d.to_string()), n),
            _ => (None, g),
        };
        WELL_KNOWN
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|&(_, rid)| Entry::WellKnown { domain, rid })
            .ok_or_else(|| {
                format!("unknown group {g:?}: use @S-1-5-…, a well-known domain group, or define a [[group]]")
            })
    }
}

/// The authenticated identity of a session, as authorization sees it.
#[derive(Debug, Clone, Copy)]
pub struct Who<'a> {
    pub guest: bool,
    /// NTLM: the local `[[user]]` name; Kerberos: the client principal.
    pub user: &'a str,
    pub kerberos: bool,
    /// Verified PAC (Kerberos against AD only).
    pub pac: Option<&'a LogonInfo>,
}

/// Outcome of a TREE_CONNECT authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Denied,
    ReadOnly,
    ReadWrite,
}

fn user_matches(p: &UserPat, who: &Who, cfg: &Config) -> bool {
    if who.guest || who.user.is_empty() {
        return false;
    }
    match p {
        UserPat::Bare(n) => {
            if !who.kerberos {
                return who.user.eq_ignore_ascii_case(n);
            }
            let realm = cfg.kerberos.as_ref().and_then(|k| k.realm.as_deref());
            match (realm, who.user.rsplit_once('@')) {
                (Some(realm), Some((u, r))) => u.eq_ignore_ascii_case(n) && r.eq_ignore_ascii_case(realm),
                _ => false,
            }
        }
        UserPat::Principal(pr) => who.kerberos && who.user.eq_ignore_ascii_case(pr),
        UserPat::DomUser { domain, name } => who
            .pac
            .is_some_and(|l| l.domain.eq_ignore_ascii_case(domain) && l.user.eq_ignore_ascii_case(name)),
    }
}

fn entry_matches(e: &Entry, who: &Who, cfg: &Config) -> bool {
    if who.guest {
        return false;
    }
    match e {
        Entry::User(p) => user_matches(p, who, cfg),
        Entry::GroupSid(s) => who.pac.is_some_and(|l| l.has_sid(s)),
        Entry::WellKnown { domain, rid } => who.pac.is_some_and(|l| {
            domain.as_ref().is_none_or(|d| l.domain.eq_ignore_ascii_case(d))
                && l.domain_sid.as_ref().is_some_and(|ds| l.has_sid(&ds.with_rid(*rid)))
        }),
        Entry::Table(i) => {
            let g = &cfg.groups[*i];
            let by_sid = g
                .sid
                .as_deref()
                .and_then(Sid::parse)
                .is_some_and(|s| who.pac.is_some_and(|l| l.has_sid(&s)));
            by_sid
                || g.members
                    .iter()
                    .any(|m| UserPat::parse(m).is_ok_and(|p| user_matches(&p, who, cfg)))
        }
    }
}

/// True when any entry of `list` matches `who`. Entries were validated at
/// config load; one that no longer parses never matches.
pub fn any_matches(list: &[String], who: &Who, cfg: &Config) -> bool {
    list.iter()
        .any(|s| Entry::parse(s, cfg).is_ok_and(|e| entry_matches(&e, who, cfg)))
}

/// Decide TREE_CONNECT access to `share` for `who`.
pub fn check(cfg: &Config, share: &ShareCfg, who: &Who) -> Access {
    if any_matches(&share.invalid_users, who, cfg) {
        return Access::Denied;
    }
    if !share.valid_users.is_empty() && !any_matches(&share.valid_users, who, cfg) {
        return Access::Denied;
    }
    if share.read_only || any_matches(&share.read_only_users, who, cfg) {
        Access::ReadOnly
    } else {
        Access::ReadWrite
    }
}

/// Validate every share list and the `[[group]]` table (called by
/// `Config::validate`).
pub fn validate(cfg: &Config) -> Result<(), String> {
    let mut seen: Vec<String> = Vec::new();
    for g in &cfg.groups {
        let lower = g.name.to_lowercase();
        if g.name.trim().is_empty() || g.name.starts_with('@') || seen.contains(&lower) {
            return Err(format!("invalid or duplicate [[group]] name {:?}", g.name));
        }
        seen.push(lower);
        if g.sid.is_none() && g.members.is_empty() {
            return Err(format!("[[group]] {:?}: set sid and/or members", g.name));
        }
        if let Some(s) = &g.sid {
            Sid::parse(s).ok_or_else(|| format!("[[group]] {:?}: invalid sid {s:?}", g.name))?;
        }
        for m in &g.members {
            if m.trim_start().starts_with('@') {
                return Err(format!("[[group]] {:?}: member {m:?} is a group (no nesting)", g.name));
            }
            UserPat::parse(m).map_err(|e| format!("[[group]] {:?}: {e}", g.name))?;
        }
    }
    for s in &cfg.shares {
        validate_share(cfg, s)?;
    }
    Ok(())
}

/// Validate one share's user lists against `cfg`'s `[[group]]` table.
pub fn validate_share(cfg: &Config, s: &ShareCfg) -> Result<(), String> {
    for (key, list) in [
        ("valid_users", &s.valid_users),
        ("invalid_users", &s.invalid_users),
        ("read_only_users", &s.read_only_users),
    ] {
        for e in list {
            Entry::parse(e, cfg).map_err(|err| format!("share {:?} {key}: {err}", s.name))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(extra: &str) -> Config {
        let raw = format!(
            "{extra}\n[[share]]\nname = \"s\"\npath = \"/\"\n"
        );
        let c: Config = toml::from_str(&raw).unwrap();
        validate(&c).unwrap();
        c
    }

    fn share(c: &Config, valid: &[&str], invalid: &[&str], ro: &[&str]) -> ShareCfg {
        let v = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let s = ShareCfg {
            name: "s".into(),
            path: "/".into(),
            valid_users: v(valid),
            invalid_users: v(invalid),
            read_only_users: v(ro),
            ..Default::default()
        };
        validate_share(c, &s).unwrap();
        s
    }

    fn ntlm(user: &str) -> Who<'_> {
        Who { guest: false, user, kerberos: false, pac: None }
    }

    fn krb<'a>(user: &'a str, pac: Option<&'a LogonInfo>) -> Who<'a> {
        Who { guest: false, user, kerberos: true, pac }
    }

    const DOM: &str = "S-1-5-21-1-2-3";

    fn pac(user: &str, rids: &[u32], extra: &[&str]) -> LogonInfo {
        let d = Sid::parse(DOM).unwrap();
        let mut groups: Vec<Sid> = rids.iter().map(|r| d.with_rid(*r)).collect();
        groups.extend(extra.iter().map(|s| Sid::parse(s).unwrap()));
        LogonInfo {
            user: user.into(),
            domain: "AD".into(),
            user_sid: Some(d.with_rid(1104)),
            domain_sid: Some(d),
            groups,
        }
    }

    #[test]
    fn no_lists_allows_everyone_read_write() {
        let c = cfg("");
        let s = share(&c, &[], &[], &[]);
        assert_eq!(check(&c, &s, &ntlm("bob")), Access::ReadWrite);
        let guest = Who { guest: true, user: "", kerberos: false, pac: None };
        assert_eq!(check(&c, &s, &guest), Access::ReadWrite);
    }

    #[test]
    fn principal_match() {
        let c = cfg("[kerberos]\nrealm = \"AD.G8.LO\"");
        let s = share(&c, &["alice", "carol@OTHER.REALM"], &["mallory"], &["dave"]);
        assert_eq!(check(&c, &s, &ntlm("Alice")), Access::ReadWrite);
        assert_eq!(check(&c, &s, &ntlm("bob")), Access::Denied);
        // Bare name: Kerberos only in the configured realm.
        assert_eq!(check(&c, &s, &krb("alice@AD.G8.LO", None)), Access::ReadWrite);
        assert_eq!(check(&c, &s, &krb("alice@EVIL.REALM", None)), Access::Denied);
        // Full principal: Kerberos only, exact realm.
        assert_eq!(check(&c, &s, &krb("carol@other.realm", None)), Access::ReadWrite);
        assert_eq!(check(&c, &s, &ntlm("carol@OTHER.REALM")), Access::Denied);
        // Guests never match valid_users.
        let guest = Who { guest: true, user: "", kerberos: false, pac: None };
        assert_eq!(check(&c, &s, &guest), Access::Denied);
        // invalid_users wins even without valid_users.
        let s2 = share(&c, &[], &["mallory"], &["dave"]);
        assert_eq!(check(&c, &s2, &ntlm("MALLORY")), Access::Denied);
        assert_eq!(check(&c, &s2, &ntlm("dave")), Access::ReadOnly);
        assert_eq!(check(&c, &s2, &ntlm("erin")), Access::ReadWrite);
    }

    #[test]
    fn bare_name_without_realm_never_matches_kerberos() {
        let c = cfg("");
        let s = share(&c, &["alice"], &[], &[]);
        assert_eq!(check(&c, &s, &krb("alice@AD.G8.LO", None)), Access::Denied);
    }

    #[test]
    fn read_only_share_stays_read_only() {
        let c = cfg("");
        let mut s = share(&c, &["bob"], &[], &[]);
        s.read_only = true;
        assert_eq!(check(&c, &s, &ntlm("bob")), Access::ReadOnly);
    }

    #[test]
    fn pac_groups() {
        let c = cfg(
            "[[group]]\nname = \"share-readers\"\nsid = \"S-1-5-21-1-2-3-1105\"\n\
             [[group]]\nname = \"ops\"\nmembers = [\"bob\", \"AD\\\\zed\"]",
        );
        let s = share(
            &c,
            &["@Domain Admins", "@share-readers", "@S-1-5-21-9-9-9-7", "@ops", "AD\\eve"],
            &[],
            &["@share-readers"],
        );
        let admin = pac("root", &[513, 512], &[]);
        let reader = pac("rita", &[513, 1105], &[]);
        let foreign = pac("fred", &[513], &["S-1-5-21-9-9-9-7"]);
        let plain = pac("pat", &[513], &[]);
        let zed = pac("zed", &[513], &[]);
        let eve = pac("eve", &[513], &[]);
        assert_eq!(check(&c, &s, &krb("root@AD.G8.LO", Some(&admin))), Access::ReadWrite);
        assert_eq!(check(&c, &s, &krb("rita@AD.G8.LO", Some(&reader))), Access::ReadOnly);
        assert_eq!(check(&c, &s, &krb("fred@AD.G8.LO", Some(&foreign))), Access::ReadWrite);
        assert_eq!(check(&c, &s, &krb("pat@AD.G8.LO", Some(&plain))), Access::Denied);
        assert_eq!(check(&c, &s, &krb("zed@AD.G8.LO", Some(&zed))), Access::ReadWrite);
        assert_eq!(check(&c, &s, &krb("eve@AD.G8.LO", Some(&eve))), Access::ReadWrite);
        // Without a PAC (MIT KDC, NTLM) group entries don't match…
        assert_eq!(check(&c, &s, &krb("root@AD.G8.LO", None)), Access::Denied);
        // …but [[group]] members do.
        assert_eq!(check(&c, &s, &ntlm("bob")), Access::ReadWrite);
    }

    #[test]
    fn well_known_group_checks_domain() {
        let c = cfg("");
        let s = share(&c, &["@OTHER\\Domain Admins"], &[], &[]);
        let admin = pac("root", &[512], &[]);
        assert_eq!(check(&c, &s, &krb("root@AD.G8.LO", Some(&admin))), Access::Denied);
        let s = share(&c, &["@ad\\domain admins"], &[], &[]);
        assert_eq!(check(&c, &s, &krb("root@AD.G8.LO", Some(&admin))), Access::ReadWrite);
    }

    #[test]
    fn bad_entries_rejected_at_load() {
        for (extra, share_line) in [
            ("", "valid_users = [\"@nosuchgroup\"]"),
            ("", "valid_users = [\"@S-1-5-x\"]"),
            ("", "invalid_users = [\"\"]"),
            ("", "read_only_users = [\"\\\\bob\"]"),
            ("", "valid_users = [\"@alice@\"]"),
            ("[[group]]\nname = \"g\"", ""),
            ("[[group]]\nname = \"g\"\nsid = \"S-1\"", ""),
            ("[[group]]\nname = \"g\"\nmembers = [\"@h\"]", ""),
            ("[[group]]\nname = \"g\"\nmembers = [\"a\"]\n[[group]]\nname = \"G\"\nmembers = [\"b\"]", ""),
        ] {
            let raw = format!("{extra}\n[[share]]\nname = \"s\"\npath = \"/\"\n{share_line}\n");
            let c: Config = toml::from_str(&raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert!(validate(&c).is_err(), "accepted:\n{raw}");
        }
    }
}
