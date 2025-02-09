use crate::utils::ParsingStatus;
use anyhow::*;
use regex::Regex;
use std::{net::IpAddr, str::FromStr};

#[allow(clippy::bind_instead_of_map)]
pub fn parse(
    line: &str,
    ip: Option<&Regex>,
    positive: Option<&String>,
    negative: Option<&String>,
) -> Result<ParsingStatus> {
    if let Some(ne) = negative {
        if line.contains(ne) {
            return Ok(ParsingStatus::OkEntry);
        }
    }

    if let Some(po) = positive {
        if !line.contains(po) {
            return Ok(ParsingStatus::OkEntry);
        }
    }

    let ip = ip.unwrap().captures(line);

    let ip = ip
        .and_then(|c| c.get(1))
        .and_then(|g| Some(g.as_str()))
        .and_then(|e| IpAddr::from_str(e).ok())
        .ok_or_else(|| anyhow!("cant parse clf line - ip"))?;

    Ok(ParsingStatus::BadEntry(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAILED: &str =
        "Sep 26 06:25:19 livecompute sshd[23246]: Failed password for root from 179.124.36.195 port 41883 ssh2";

    const SUCCESS: &str =
        "Sep 26 06:25:19 livecompute sshd[23246]: Successful login for root from 179.124.36.195 port 41883 ssh2";

    // generic log positive regex - what's that's flagged by this is considered bad, the rest is good
    #[test]
    fn positive() {
        let positive = "Failed password".to_string();
        let ip = Regex::new(r"from ([0-9a-fA-F:.]+) port").unwrap();

        let ret = parse(FAILED, Some(&ip), Some(&positive), None).unwrap();
        match ret {
            ParsingStatus::BadEntry(_) => {}
            _ => panic!("bad parsing"),
        }

        let ret = parse(SUCCESS, Some(&ip), Some(&positive), None).unwrap();
        match ret {
            ParsingStatus::OkEntry => {}
            _ => panic!("bad parsing"),
        }
    }

    // generic log negative regex - what's that's flagged by this is considered good, the rest is bad
    #[test]
    fn negative() {
        let negative = "Successful login".to_string();
        let ip = Regex::new(r"from ([0-9a-fA-F:.]+) port").unwrap();

        let ret = parse(SUCCESS, Some(&ip), None, Some(&negative)).unwrap();
        match ret {
            ParsingStatus::OkEntry => {}
            _ => panic!("bad parsing"),
        }

        let ret = parse(FAILED, Some(&ip), None, Some(&negative)).unwrap();
        match ret {
            ParsingStatus::BadEntry(_) => {}
            _ => panic!("bad parsing"),
        }
    }
}
