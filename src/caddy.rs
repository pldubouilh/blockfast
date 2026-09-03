use crate::probes::ProbeList;
use crate::utils::ParsingStatus;
use anyhow::*;
use std::{net::IpAddr, str::FromStr};

pub fn parse(line: &str, probelist: &ProbeList, invalid_statuses: &[u32]) -> Result<ParsingStatus> {
    let json: serde_json::Value = serde_json::from_str(line)?;

    let remote_ip = json
        .get("request")
        .and_then(|r| r.get("remote_ip"))
        .and_then(|r| r.as_str())
        .and_then(|r| IpAddr::from_str(r).ok())
        .ok_or_else(|| anyhow!("cant parse json line - remote_ip"))?;

    let uri = json
        .get("request")
        .and_then(|r| r.get("uri"))
        .and_then(|r| r.as_str())
        .ok_or_else(|| anyhow!("cant parse json line - uri"))?;

    let status = json
        .get("status")
        .and_then(|r| r.as_u64())
        .ok_or_else(|| anyhow!("cant parse json line - status"))? as u32;

    if let Some(probe) = probelist.check(uri, status) {
        return Ok(ParsingStatus::BadEntry(remote_ip, probe.allowance));
    }

    let is_bad_status = invalid_statuses.iter().any(|s| s == &status);
    if is_bad_status {
        return Ok(ParsingStatus::BadEntry(remote_ip, None));
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
            let ret = parse(*e, &ProbeList::builtin(), &vec![429, 401]).unwrap();
            match ret {
                ParsingStatus::BadEntry(..) => {}
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
            let ret = parse(*e, &ProbeList::builtin(), &vec![429, 401]).unwrap();
            match ret {
                ParsingStatus::OkEntry => {}
                _ => panic!("bad parsing"),
            }
        })
    }

    #[test]
    fn probe_uri() {
        // a probe path is an offence even with a 200 status and no status list
        let bad = r#"{"request":{"remote_ip":"1.2.3.4","uri":"/.env"},"status":200}"#;
        match parse(bad, &ProbeList::builtin(), &[]).unwrap() {
            ParsingStatus::BadEntry(..) => {}
            _ => panic!("bad parsing"),
        }

        let ok = r#"{"request":{"remote_ip":"1.2.3.4","uri":"/api/auth/me"},"status":200}"#;
        match parse(ok, &ProbeList::builtin(), &[]).unwrap() {
            ParsingStatus::OkEntry => {}
            _ => panic!("bad parsing"),
        }
    }

    #[test]
    fn malformed() {
        let vectors = [
            r#"{"level":"info","ts":1738064403.2176833,"logger":"http.log.access.log0","msg":"handled request","requeto":"HTTP/1 x86_64; rv:133.0)"],"Server":["Caddy"]}}"#,
        ];

        vectors.iter().for_each(|e| {
            let ret = parse(*e, &ProbeList::builtin(), &vec![429, 401]);
            assert!(ret.is_err());
        })
    }
}
