use std::net::IpAddr;

use lazy_static::lazy_static;

// TODO: allow user-provided list
// TODO: match different error-levels (10 404, but only 5 401, etc...)
lazy_static! {
    static ref BAD_STATUSES: [&'static str; 2] = ["401", "429"];
}

pub fn parse(line: &str) -> Option<IpAddr> {
    // TODO: Use a proper parser ?
    let elts: Vec<&str> = line.split_whitespace().collect();
    let ip = elts[0].parse::<IpAddr>().ok();
    let http_code = elts[elts.len() - 2] as &str;

    BAD_STATUSES.iter().find_map(
        |bad_status| {
            if http_code == *bad_status {
                ip
            } else {
                None
            }
        },
    )
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

        vectors.iter().for_each(|e| assert!(parse(*e).is_some()))
    }

    #[test]
    fn negative() {
        let vectors = [
            "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 200 923",
            "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 404 923",
        ];

        vectors.iter().for_each(|e| assert!(parse(*e).is_none()))
    }
}
