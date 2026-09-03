use crate::probes::ProbeList;
use crate::utils::ParsingStatus;
use anyhow::*;
use lazy_static::lazy_static;
use regex::Regex;
use std::{net::IpAddr, str::FromStr};

lazy_static! {
    // anchored on the left side of the line: host, ident, authuser, [date],
    // the quoted request (honouring backslash escapes, so a quote injected in
    // the URL cannot shift the match), then the status right after it. this
    // covers plain CLF and the combined format - the trailing attacker
    // controlled "referer" "user-agent" fields are never scanned
    static ref RE_CLF: Regex =
        Regex::new(r#"^(\S+)\s+\S+\s+\S+\s+\[[^\]]*\]\s+"((?:[^"\\]|\\.)*)"\s+(\d{3})(?:\s|$)"#)
            .unwrap();
}

pub fn parse(line: &str, probelist: &ProbeList, invalid_statuses: &[u32]) -> Result<ParsingStatus> {
    let caps = RE_CLF
        .captures(line)
        .ok_or_else(|| anyhow!("cant parse clf line"))?;

    let ip = caps
        .get(1)
        .and_then(|g| IpAddr::from_str(g.as_str()).ok())
        .ok_or_else(|| anyhow!("cant parse clf line - ip"))?;

    let status = caps
        .get(3)
        .and_then(|g| g.as_str().parse::<u32>().ok())
        .ok_or_else(|| anyhow!("cant parse clf line - status"))?;

    // the uri is the second token of the request field ("GET /uri HTTP/1.1")
    let uri = caps
        .get(2)
        .and_then(|g| g.as_str().split_whitespace().nth(1));
    if let Some(u) = uri {
        if let Some(probe) = probelist.check(u, status) {
            return Ok(ParsingStatus::BadEntry(ip, probe.allowance));
        }
    }

    let is_bad_status = invalid_statuses.iter().any(|s| s == &status);
    if is_bad_status {
        return Ok(ParsingStatus::BadEntry(ip, None));
    }

    Ok(ParsingStatus::OkEntry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive() {
        let vectors = [
            "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 401 923",
            "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 429 923",
        ];

        vectors.iter().for_each(|e| {
            let ret = parse(*e, &ProbeList::builtin(), &vec![401, 429]).unwrap();
            match ret {
                ParsingStatus::BadEntry(..) => {}
                _ => panic!("bad parsing"),
            }
        })
    }

    #[test]
    fn negative() {
        let vectors = [
            "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 200 923",
            "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 404 923",
        ];

        vectors.iter().for_each(|e| {
            let ret = parse(*e, &ProbeList::builtin(), &vec![401, 429]).unwrap();
            match ret {
                ParsingStatus::OkEntry => {}
                _ => panic!("bad parsing"),
            }
        })
    }

    #[test]
    fn combined_format() {
        // combined log format appends "referer" "user-agent" - the old parser
        // read digits out of the user-agent as the status and silently missed these
        let bad = r#"8.8.8.8 - - [25/Sep/2021:13:49:56 +0200] "GET /admin HTTP/1.1" 401 923 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0""#;
        match parse(bad, &ProbeList::builtin(), &vec![401, 429]).unwrap() {
            ParsingStatus::BadEntry(..) => {}
            _ => panic!("bad parsing"),
        }

        let ok = r#"8.8.8.8 - - [25/Sep/2021:13:49:56 +0200] "GET / HTTP/1.1" 200 923 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0""#;
        match parse(ok, &ProbeList::builtin(), &vec![401, 429]).unwrap() {
            ParsingStatus::OkEntry => {}
            _ => panic!("bad parsing"),
        }
    }

    #[test]
    fn probe_uri() {
        // a probe path is an offence even with a 200 status and no status list
        let bad = r#"8.8.8.8 - - [25/Sep/2021:13:49:56 +0200] "GET /.env HTTP/1.1" 200 923"#;
        match parse(bad, &ProbeList::builtin(), &[]).unwrap() {
            ParsingStatus::BadEntry(..) => {}
            _ => panic!("bad parsing"),
        }

        let ok = r#"8.8.8.8 - - [25/Sep/2021:13:49:56 +0200] "GET /index.html HTTP/1.1" 200 923"#;
        match parse(ok, &ProbeList::builtin(), &[]).unwrap() {
            ParsingStatus::OkEntry => {}
            _ => panic!("bad parsing"),
        }
    }

    #[test]
    fn quote_injection() {
        // servers escape quotes in the logged request - an escaped `\" 401 `
        // inside the URL must not be mistaken for the end of the request field
        let ok = r#"8.8.8.8 - - [25/Sep/2021:13:49:56 +0200] "GET /x?a=\" 401 - HTTP/1.1" 200 923"#;
        match parse(ok, &ProbeList::builtin(), &vec![401, 429]).unwrap() {
            ParsingStatus::OkEntry => {}
            _ => panic!("bad parsing"),
        }
    }

    #[test]
    fn bodyless() {
        // CLF uses `-` for absent body bytes, both branches must still parse
        let bad = "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"GET / HTTP/2.0\" 401 -";
        match parse(bad, &ProbeList::builtin(), &vec![401, 429]).unwrap() {
            ParsingStatus::BadEntry(..) => {}
            _ => panic!("bad parsing"),
        }

        let ok = "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"GET / HTTP/2.0\" 304 -";
        match parse(ok, &ProbeList::builtin(), &vec![401, 429]).unwrap() {
            ParsingStatus::OkEntry => {}
            _ => panic!("bad parsing"),
        }
    }

    #[test]
    fn malformed() {
        let vectors = [
            "8.8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 200 923",
            "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\"",
        ];

        vectors.iter().for_each(|e| {
            let ret = parse(*e, &ProbeList::builtin(), &vec![429, 401]);
            assert!(ret.is_err());
        })
    }
}
