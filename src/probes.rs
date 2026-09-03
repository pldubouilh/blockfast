// scanner/vulnerability-probe detection for the clf and caddy parsers.
//
// probes come either from the built-in list below (distilled from real caddy
// logs + well-known probe paths), or from a probelist JSON file (--probelist),
// meant to be generated per-setup, e.g. by feeding logs to an AI system:
//
// {
//   "probes": [
//     { "path": "/.env", "match": "contains" },
//     { "path": "/test.php", "match": "exact" },
//     { "path": "/api/auth", "match": "prefix", "status": "401", "allowance": 10 }
//   ]
// }
//
// `match` is exact | prefix | contains (default contains). exact and prefix
// apply to the query-stripped path, contains to the whole uri - all lowercased.
// `status` restricts the probe to those response statuses (same syntax as
// --invalid-http-statuses, e.g. "401,4xx"); without it any status matches.
// `allowance` overrides the global --allowance for this probe. a `comment`
// field is allowed anywhere and ignored.

use anyhow::*;
use std::path::Path;
use std::result::Result::Ok;

use crate::utils::parse_statuses;

// built-in probes, matched anywhere in the lowercased uri (query included).
// deliberately conservative: only paths that no legitimate client of ANY
// common stack ever requests. more aggressive, setup-specific rules (e.g.
// wp-login.php, /actuator, hosted admin consoles) belong in a --probelist file.
const PROBE_PARTS: &[&str] = &[
    // secrets & dotfiles
    "/.env",  // /.env, /.env.bak, /backend/.env, ...
    "%2eenv", // url-encoded .env probes
    "/.git",  // /.git/config, /.git/HEAD, /.gitconfig
    "/.svn",
    "/.hg/",
    "/.aws", // /.aws/credentials
    "/.ssh",
    "/.docker",
    // cloud credentials & config dumps
    "credentials.json", // /google-credentials.json, /application_default_credentials.json
    "-key.json",        // /gcp-key.json, /firebase-key.json
    "/keyfile.json",
    "/sa.json",
    "service-account.json",
    "firebase-adminsdk.json",
    "gcp-sa.json",
    "/docker-compose.yml",
    "/appsettings.json",
    "application.yml",
    "parameters.yml",
    "/web.config",
    "/settings.py",
    "/wp-config.php", // never served, only probed - even on real wordpress sites
    // php probes
    "phpinfo", // /phpinfo.php, /admin/phpinfo.php, /?phpinfo=1
    "phpmyadmin",
    "adminer.php",
    ".php.bak",
    ".php.old",
    ".php.save",
    ".php~",
    "eval-stdin.php", // phpunit RCE
    "/vendor/phpunit",
    // wordpress fingerprinting (legit wordpress traffic never touches this)
    "wlwmanifest.xml",
    // framework debug/env endpoints
    "/actuator/env", // spring boot (bare /actuator would catch legit health checks)
    "/_profiler",    // symfony
    "/_ignition",    // laravel RCE
    "/_environment", // cakephp
    "laravel.log",
    // server status
    "server-status",
    "server-info",
    // traversal & IoT/router botnets
    "/../",
    "%2e%2e",
    "/etc/passwd",
    "/cgi-bin/",
    "/boaform",
    "/hnap1",
    "/gponform",
];

// built-in exact matches on the query-stripped path: names too short or
// generic to be safe as substrings (/i.php would match /api.php, etc..)
const PROBE_EXACT: &[&str] = &[
    "/test.php",
    "/info.php",
    "/pinfo.php",
    "/pi.php",
    "/i.php",
    "/p.php",
    "/php.php",
    "/debug.php",
    "/database.php",
    "/config.php",
    "/shell.php",
    "/upload.php",
    "/env",
];

pub enum MatchKind {
    Exact,
    Prefix,
    Contains,
}

pub struct Probe {
    pub path: String,
    pub kind: MatchKind,
    pub statuses: Option<Vec<u32>>,
    pub allowance: Option<u8>,
}

pub struct ProbeList {
    probes: Vec<Probe>,
}

impl ProbeList {
    pub fn builtin() -> ProbeList {
        let mut probes: Vec<Probe> = vec![];
        for p in PROBE_PARTS {
            probes.push(Probe {
                path: p.to_string(),
                kind: MatchKind::Contains,
                statuses: None,
                allowance: None,
            });
        }
        for p in PROBE_EXACT {
            probes.push(Probe {
                path: p.to_string(),
                kind: MatchKind::Exact,
                statuses: None,
                allowance: None,
            });
        }
        ProbeList { probes }
    }

    pub fn load(path: &Path) -> Result<ProbeList> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cant read probelist {:?}", path))?;
        ProbeList::from_json(&raw).with_context(|| format!("cant parse probelist {:?}", path))
    }

    fn from_json(raw: &str) -> Result<ProbeList> {
        let json: serde_json::Value = serde_json::from_str(raw)?;
        let arr = json
            .get("probes")
            .and_then(|p| p.as_array())
            .ok_or_else(|| anyhow!("missing `probes` array"))?;

        let mut probes = vec![];
        for (i, p) in arr.iter().enumerate() {
            // entries carrying only a comment are section separators, skip them
            if p.get("path").is_none() && p.get("comment").is_some() {
                continue;
            }

            let path = p
                .get("path")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("probe #{}: missing `path`", i))?
                .to_ascii_lowercase();

            let kind = match p
                .get("match")
                .and_then(|v| v.as_str())
                .unwrap_or("contains")
            {
                "exact" => MatchKind::Exact,
                "prefix" => MatchKind::Prefix,
                "contains" => MatchKind::Contains,
                other => bail!("probe #{}: unknown match kind `{}`", i, other),
            };

            let statuses = match p.get("status") {
                None => None,
                Some(v) => {
                    let s = v
                        .as_str()
                        .ok_or_else(|| anyhow!("probe #{}: `status` must be a string", i))?;
                    Some(parse_statuses(s).with_context(|| format!("probe #{}", i))?)
                }
            };

            let allowance = match p.get("allowance") {
                None => None,
                Some(v) => {
                    let a = v
                        .as_u64()
                        .filter(|a| (1..=255).contains(a))
                        .ok_or_else(|| anyhow!("probe #{}: `allowance` must be 1-255", i))?;
                    Some(a as u8)
                }
            };

            probes.push(Probe {
                path,
                kind,
                statuses,
                allowance,
            });
        }

        Ok(ProbeList { probes })
    }

    pub fn len(&self) -> usize {
        self.probes.len()
    }

    // returns the first probe matching this uri + response status
    pub fn check(&self, uri: &str, status: u32) -> Option<&Probe> {
        let uri = uri.to_ascii_lowercase();
        let path = uri.split(['?', '#']).next().unwrap_or(&uri);

        self.probes.iter().find(|p| {
            let path_hit = match p.kind {
                MatchKind::Exact => path == p.path,
                MatchKind::Prefix => path.starts_with(&p.path),
                MatchKind::Contains => uri.contains(&p.path),
            };
            path_hit && p.statuses.as_ref().is_none_or(|s| s.contains(&status))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_positive() {
        // all straight out of real scanner traffic
        let vectors = [
            "/.env",
            "/.env.backup",
            "/config/.env",
            "/%2E%2E%2f%2Eenv",
            "/.git/config",
            "/.aws/credentials",
            "/phpinfo.php",
            "/admin/phpinfo.php",
            "/?phpinfo=1",
            "/wp-includes/wlwmanifest.xml",
            "/blog/wp-includes/wlwmanifest.xml",
            "/wp-config.php.bak",
            "/config.php",
            "/google-credentials.json",
            "/gcp-key.json",
            "/docker-compose.yml",
            "/_profiler/phpinfo",
            "/_ignition/health-check",
            "/storage/logs/laravel.log",
            "/actuator/env",
            "/webroot/index.php/_environment",
            "/test.php",
            "/i.php",
            "/env",
            "/phpMyAdmin/index.php",
            "/cgi-bin/luci",
            "/../.env",
            "/server-status.php",
        ];

        let pl = ProbeList::builtin();
        vectors.iter().for_each(|e| {
            assert!(pl.check(e, 200).is_some(), "should flag {}", e);
        })
    }

    #[test]
    fn builtin_negative() {
        // real user traffic from the same logs
        let vectors = [
            "/",
            "/db",
            "/ui/",
            "/ui/static/js/utils.js",
            "/api/auth",
            "/api/users/1",
            "/api/channels/5/messages?after=1620&limit=200",
            "/app.js",
            "/config.json",
            "/favicon.ico",
            "/robots.txt",
            "/.well-known/acme-challenge/token123",
            "/api.php",
            "/information",
            "/environment-report",
            // legit traffic on stacks the tight default must not break:
            "/wp-login.php",                  // wordpress logins
            "/xmlrpc.php",                    // wordpress apps/jetpack
            "/?rest_route=/wp/v2/posts",      // wordpress REST
            "/actuator/health",               // spring boot health checks
            "/autodiscover/autodiscover.xml", // outlook probes any domain
            "/solr/admin/ping",               // hosted consoles
            "/composer.json",
        ];

        let pl = ProbeList::builtin();
        vectors.iter().for_each(|e| {
            assert!(pl.check(e, 200).is_none(), "should not flag {}", e);
        })
    }

    #[test]
    fn probelist_file() {
        let raw = r#"{
            "comment": "generated probelist",
            "probes": [
                { "comment": "--- section separator, ignored ---" },
                { "path": "/.env" },
                { "path": "/test.php", "match": "exact" },
                { "path": "/api/auth", "match": "prefix", "status": "401,4xx", "allowance": 10, "comment": "stuffers" }
            ]
        }"#;
        let pl = ProbeList::from_json(raw).unwrap();
        assert_eq!(pl.len(), 3);

        // contains, any status
        assert!(pl.check("/backend/.env", 200).is_some());
        // exact, query-stripped
        assert!(pl.check("/test.php?x=1", 200).is_some());
        assert!(pl.check("/xtest.php", 200).is_none());
        // prefix + status filter + allowance override
        let hit = pl.check("/api/auth/me", 401).unwrap();
        assert_eq!(hit.allowance, Some(10));
        assert!(pl.check("/api/auth/me", 200).is_none());
        assert!(pl.check("/api/authless", 401).is_some()); // prefix is a plain str prefix
    }

    #[test]
    fn probelist_rejects_garbage() {
        assert!(ProbeList::from_json("{}").is_err());
        assert!(ProbeList::from_json(r#"{"probes": [{}]}"#).is_err());
        assert!(ProbeList::from_json(r#"{"probes": [{"path": ""}]}"#).is_err());
        assert!(ProbeList::from_json(r#"{"probes": [{"path": "/x", "match": "regex"}]}"#).is_err());
        assert!(ProbeList::from_json(r#"{"probes": [{"path": "/x", "status": 401}]}"#).is_err());
        assert!(ProbeList::from_json(r#"{"probes": [{"path": "/x", "status": "9xx"}]}"#).is_err());
        assert!(ProbeList::from_json(r#"{"probes": [{"path": "/x", "allowance": 300}]}"#).is_err());
        assert!(ProbeList::from_json(r#"{"probes": [{"path": "/x", "allowance": 0}]}"#).is_err());
    }
}
