use crate::utils::ParsingStatus;
use anyhow::Result;
use lazy_static::lazy_static;
use std::net::IpAddr;

// TODO: allow user-provided list
// TODO: match different error-levels (10 404, but only 5 401, etc...)
lazy_static! {
    static ref BAD_STATUSES: [u32; 2] = [401, 429];
}

pub fn parse(line: &str) -> Result<ParsingStatus> {
    // TODO: Use a proper parser ?
    let elts: Vec<&str> = line.split_whitespace().collect();

    let ip_str = elts[0];
    let ip = ip_str.parse::<IpAddr>()?;

    let http_code_str = elts[elts.len() - 2] as &str;
    let http_code = http_code_str.parse::<u32>()?;

    for status in BAD_STATUSES.iter() {
        if *status == http_code {
            return Ok(ParsingStatus::BadEntry(ip));
        }
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
            "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 200 923",
            "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 404 923",
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
            "8.8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 200 923",
            "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\"",
        ];

        vectors.iter().for_each(|e| {
            let ret = parse(*e);
            assert!(ret.is_err());
        })
    }
}
