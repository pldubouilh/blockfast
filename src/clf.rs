use crate::utils::ParsingStatus;
use anyhow::*;
use lazy_static::lazy_static;
use regex::Regex;
use std::{net::IpAddr, str::FromStr};

lazy_static! {
    static ref RE_IP: Regex = Regex::new(r"^(\S+)\s").unwrap();
    static ref RE_STATUS: Regex = Regex::new(r"(\d+)\s(\w+)$").unwrap();
}

#[allow(clippy::bind_instead_of_map)]
pub fn parse(line: &str, valid_statuses: &[u32]) -> Result<ParsingStatus> {
    let ip = RE_IP
        .captures(line)
        .and_then(|c| c.get(1))
        .and_then(|g| Some(g.as_str()))
        .and_then(|e| IpAddr::from_str(e).ok())
        .ok_or_else(|| anyhow!("cant parse clf line - ip"))?;

    let status = RE_STATUS
        .captures(line)
        .and_then(|c| c.get(1))
        .and_then(|g| Some(g.as_str()))
        .and_then(|e| e.parse::<u32>().ok())
        .ok_or_else(|| anyhow!("cant parse clf line - status"))?;

    let is_good_status = valid_statuses.iter().any(|s| s == &status);
    if !is_good_status {
        return Ok(ParsingStatus::BadEntry(ip));
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
            let ret = parse(*e, &vec![200, 404]).unwrap();
            match ret {
                ParsingStatus::BadEntry(_) => {}
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
            let ret = parse(*e, &vec![200, 404]).unwrap();
            match ret {
                ParsingStatus::OkEntry => {}
                _ => panic!("bad parsing"),
            }
        })
    }

    #[test]
    fn malformed() {
        let vectors = [
            "8.8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 200 923",
            "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\"",
        ];

        vectors.iter().for_each(|e| {
            let ret = parse(*e, &vec![200, 404]);
            assert!(ret.is_err());
        })
    }
}
