use crate::utils::ParsingStatus;
use anyhow::*;
use std::{net::IpAddr, str::FromStr};

pub fn parse(line: &str, valid_statuses: &[u32]) -> Result<ParsingStatus> {
    let json: serde_json::Value = serde_json::from_str(line)?;

    let remote_ip = json
        .get("request")
        .and_then(|r| r.get("remote_ip"))
        .and_then(|r| r.as_str())
        .and_then(|r| IpAddr::from_str(r).ok())
        .ok_or_else(|| anyhow!("cant parse json line - remote_ip"))?;

    let status = json
        .get("status")
        .and_then(|r| r.as_u64())
        .ok_or_else(|| anyhow!("cant parse json line - status"))?;

    let is_good_status = valid_statuses.iter().any(|s| s == &(status as u32));
    if !is_good_status {
        return Ok(ParsingStatus::BadEntry(remote_ip));
    }

    Ok(ParsingStatus::OkEntry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive() {
        let vectors = [
            r#"{"level":"info","ts":1738064403.2176833,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"46884","client_ip":"127.0.0.1","proto":"HTTP/1.1","method":"GET","host":"127.0.0.1:8009","uri":"/","headers":{"User-Agent":["Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"],"Sec-Fetch-Dest":["document"],"Sec-Fetch-Mode":["navigate"],"Accept-Language":["en-US,en;q=0.5"],"Accept-Encoding":["gzip, deflate, br, zstd"],"Connection":["keep-alive"],"Upgrade-Insecure-Requests":["1"],"Sec-Fetch-Site":["cross-site"],"Priority":["u=0, i"],"Accept":["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"]}},"bytes_read":0,"user_id":"","duration":0.002135063,"size":35133,"status":429,"resp_headers":{"Vary":["Accept, Accept-Encoding"],"Last-Modified":["Tue, 28 Jan 2025 12:40:02 GMT"],"Content-Type":["text/html; charset=utf-8"],"Server":["Caddy"]}}"#,
            r#"{"level":"info","ts":1738064403.2176833,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"46884","client_ip":"127.0.0.1","proto":"HTTP/1.1","method":"GET","host":"127.0.0.1:8009","uri":"/","headers":{"User-Agent":["Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"],"Sec-Fetch-Dest":["document"],"Sec-Fetch-Mode":["navigate"],"Accept-Language":["en-US,en;q=0.5"],"Accept-Encoding":["gzip, deflate, br, zstd"],"Connection":["keep-alive"],"Upgrade-Insecure-Requests":["1"],"Sec-Fetch-Site":["cross-site"],"Priority":["u=0, i"],"Accept":["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"]}},"bytes_read":0,"user_id":"","duration":0.002135063,"size":35133,"status":401,"resp_headers":{"Vary":["Accept, Accept-Encoding"],"Last-Modified":["Tue, 28 Jan 2025 12:40:02 GMT"],"Content-Type":["text/html; charset=utf-8"],"Server":["Caddy"]}}"#,
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
            r#"{"level":"info","ts":1738064403.2176833,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"46884","client_ip":"127.0.0.1","proto":"HTTP/1.1","method":"GET","host":"127.0.0.1:8009","uri":"/","headers":{"User-Agent":["Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"],"Sec-Fetch-Dest":["document"],"Sec-Fetch-Mode":["navigate"],"Accept-Language":["en-US,en;q=0.5"],"Accept-Encoding":["gzip, deflate, br, zstd"],"Connection":["keep-alive"],"Upgrade-Insecure-Requests":["1"],"Sec-Fetch-Site":["cross-site"],"Priority":["u=0, i"],"Accept":["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"]}},"bytes_read":0,"user_id":"","duration":0.002135063,"size":35133,"status":200,"resp_headers":{"Vary":["Accept, Accept-Encoding"],"Last-Modified":["Tue, 28 Jan 2025 12:40:02 GMT"],"Content-Type":["text/html; charset=utf-8"],"Server":["Caddy"]}}"#,
            r#"{"level":"info","ts":1738064403.2176833,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"46884","client_ip":"127.0.0.1","proto":"HTTP/1.1","method":"GET","host":"127.0.0.1:8009","uri":"/","headers":{"User-Agent":["Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"],"Sec-Fetch-Dest":["document"],"Sec-Fetch-Mode":["navigate"],"Accept-Language":["en-US,en;q=0.5"],"Accept-Encoding":["gzip, deflate, br, zstd"],"Connection":["keep-alive"],"Upgrade-Insecure-Requests":["1"],"Sec-Fetch-Site":["cross-site"],"Priority":["u=0, i"],"Accept":["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"]}},"bytes_read":0,"user_id":"","duration":0.002135063,"size":35133,"status":404,"resp_headers":{"Vary":["Accept, Accept-Encoding"],"Last-Modified":["Tue, 28 Jan 2025 12:40:02 GMT"],"Content-Type":["text/html; charset=utf-8"],"Server":["Caddy"]}}"#,
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
            r#"{"level":"info","ts":1738064403.2176833,"logger":"http.log.access.log0","msg":"handled request","requeto":"HTTP/1 x86_64; rv:133.0)"],"Server":["Caddy"]}}"#,
        ];

        vectors.iter().for_each(|e| {
            let ret = parse(*e, &vec![200, 404]);
            assert!(ret.is_err());
        })
    }
}
