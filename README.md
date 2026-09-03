# blockfast

Block internets scanners fast 🍶

Features:
  - Built-in scanner detection, built for well-known probe paths (`/.env`, `/phpinfo.php`, etc...) 
  - Extends built-in scanners using your own logs. See probelist.example.json
  - Supports logs from Common Log Format (apache, nginx logs, etc...)
  - Caddy JSON log parser
  - Generic log parser (regexp)
  - Sane defaults
  - Fast ip ban with `ipset`
  - Static release builds, no libc dependency
  - Lighter alternative to fail2ban

## example
```txt
$ ./blockfast --caddy-logpath=/caddy/logs
1737927469 - starting with caddy parsing at "/tmp/caddytest"
1737927469 - jail setup, allowance 5, time 21600s
1737927477 - caddy logged offence for 9.124.36.195
1737927478 - caddy logged offence for 9.124.36.195
1737927479 - caddy logged offence for 9.124.36.195
1737927479 - caddy logged offence for 9.124.36.195
1737927480 - caddy logged offence for 9.124.36.195
1737927480 - caddy jailtime for 9.124.36.195
```

## build
see `Makefile`

## usage
```txt
$ target/debug/blockfast
Blockfast - block internets scanners fast 🍶
Author: pierre dubouilh <pldubouilh@gmail.com>

Blockfast reads logs from various sources and blocks the offending IPs using iptables and ipset.
It supports logs in Common-Log-Format (Apache, nginx, etc..), Caddy JSON and a generic logs parser.

Example:
    # block invalid http statuses from caddy
    ./blockfast --caddy-logpath=/caddy/logs

    # generic log parser example with a log text to flag, and a regex to parse the offending IP.
    ./blockfast --generic-logpath=/tmp/generictest --generic-positive='Failed password' --generic-ip='from ([0-9a-fA-F:.]+) port'

Usage: blockfast [OPTIONS]

Options:
      --jailtime <JAILTIME>
          jail time (seconds) [default: 21600]
      --allowance <ALLOWANCE>
          how many offences allowed (max 255) [default: 5]
  -v, --verbose
          log all offences
      --clf-logpath <CLF_LOGPATH>
          path of Common-Log-Format logfile (Apache, nginx, etc..), can be repeated
      --caddy-logpath <CADDY_LOGPATH>
          path of Caddy JSON logfile, can be repeated
      --probelist <PROBELIST>
          path of a probelist JSON file, replaces the built-in probe list (see README)
      --generic-logpath <GENERIC_LOGPATH>
          generic parser log file path, can be repeated
      --generic-ip <GENERIC_IP>
          generic parser ip regex
      --generic-positive <GENERIC_POSITIVE>
          generic parser positive - if a logline contains this, it is considered bad, the rest is good
      --generic-negative <GENERIC_NEGATIVE>
          generic parser negative - if a logline contains this, it is considered good, the rest is bad
      --invalid-http-statuses <INVALID_HTTP_STATUSES>
          also flag these http statuses (for CLF and Caddy logs), on top of the built-in scanner-path detection. Coma separated list, accepts ranges with XX, e.g. "403,5xx".
  -h, --help
          Print help
  -V, --version
          Print version
```
