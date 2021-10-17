use anyhow::*;
use lazy_static::lazy_static;
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;

use crate::utils::ParsingStatus;

struct Rule {
    matcher: String,
    extractor: Regex,
}

lazy_static! {
    static ref SSHD_BAD: [Rule; 3] = [
        Rule {
            matcher: "Failed password".to_string(),
            extractor: Regex::new(r"(from.)(.*)(.port)").unwrap(),
        },
        Rule {
            matcher: "Invalid user ".to_string(),
            extractor: Regex::new(r"(from.)(.*)").unwrap(),
        },
        Rule {
            matcher: "authentication failure".to_string(),
            extractor: Regex::new(r"(rhost=)(.*)").unwrap()
        },
    ];
}

pub fn parse(line: &str) -> Result<ParsingStatus> {
    let hits = SSHD_BAD.iter().find_map(|rule| {
        if line.contains(&rule.matcher) {
            rule.extractor.captures(line)
        } else {
            None
        }
    });

    if hits.is_none() {
        return Ok(ParsingStatus::OkEntry);
    }

    let ip = hits
        .and_then(|c| c.get(2))
        .and_then(|m| IpAddr::from_str(m.as_str()).ok());

    match ip {
        Some(ip) => Ok(ParsingStatus::BadEntry(ip)),
        None => Err(anyhow!("cant parse sshd entry")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive() {
        let vectors = [
            "Sep 26 06:25:19 livecompute sshd[23246]: Failed password for root from 179.124.36.195 port 41883 ssh2",
            "Sep 26 06:26:14 livecompute sshd[23292]: pam_unix(sshd:auth): authentication failure; logname= u =0 tty=ssh ruser= rhost=5.101.107.190",
            "Sep 26 06:25:32 livecompute sshd[23254]: Invalid user neal from 35.184.211.144"
        ];

        vectors.iter().for_each(|e| {
            let ret = parse(*e).unwrap();
            match ret {
                ParsingStatus::BadEntry(_) => {}
                _ => panic!("bad parsing"),
            }
        })
    }

    #[test]
    fn negative() {
        let vectors = [
            "Sep 26 06:25:19 livecompute sshd[23246]: successful login 179.124.36.195 port 41883 ssh2",
            "Sep 26 06:26:14 livecompute sshd[23292]: pam_unix(sshd:auth): authentication total success; logname= u =0 tty=ssh ruser= rhost=5.101.107.190",
            "Sep 26 06:25:32 livecompute sshd[23254]: very good user neal from 35.184.211.144"
        ];

        vectors.iter().for_each(|e| {
            let ret = parse(*e).unwrap();
            match ret {
                ParsingStatus::OkEntry => {}
                _ => panic!("bad parsing"),
            }
        })
    }

    #[test]
    fn malformed() {
        let vectors = [
            "Sep 26 06:25:19 livecompute sshd[23246]: Failed password for root from 179.124.36.195.232 port 41883 ssh2",
            "Sep 26 06:26:14 livecompute sshd[23292]: pam_unix(sshd:auth): authentication failure; logname= u =0 tty=ssh ruser= rhost=",
        ];

        vectors.iter().for_each(|e| {
            let ret = parse(*e);
            assert!(ret.is_err());
        })
    }
}
