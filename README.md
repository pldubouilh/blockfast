# blockfast

Block internets scanners fast 🍶

Features:
  - Common Log Format parser (apache logs, etc...)
  - JSON log parser (caddy logs)
  - Generic log parser
  - Sane defaults
  - Fast ip ban with `ipset`
  - Static release builds, no libc dependency
  - Lighter alternative to fail2ban

## example
```txt
$ ./blockfast -j=/caddy/logs
1737927469 - starting with json parsing at "/tmp/jsontest"
1737927469 - jail setup, allowance 5, time 21600s
1737927477 - json logged offence for 9.124.36.195
1737927478 - json logged offence for 9.124.36.195
1737927479 - json logged offence for 9.124.36.195
1737927479 - json logged offence for 9.124.36.195
1737927480 - json logged offence for 9.124.36.195
1737927480 - json jailtime for 9.124.36.195
```

## build
see `Makefile`

## usage
```txt
$ target/debug/blockfast
Blockfast - block internets scanners fast 🍶
Author: pierre dubouilh <pldubouilh@gmail.com>

Blockfast reads logs from various sources and blocks the offending IPs using iptables and ipset.
It supports logs in Common-Log-Format (Apache, etc..), JSON (Caddy) and a generic logs parser.

Example:
    # block invalid http statuses from caddy
    ./blockfast -j=/caddy/logs

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
  -c, --clf-logpath <CLF_LOGPATH>
          path of Common-Log-Format logfile (Apache, etc..), can be repeated
  -j, --json-logpath <JSON_LOGPATH>
          path of JSON logfile (works with Caddy), can be repeated
      --generic-logpath <GENERIC_LOGPATH>
          generic parser log file path, can be repeated
      --generic-ip <GENERIC_IP>
          generic parser ip regex
      --generic-positive <GENERIC_POSITIVE>
          generic parser positive - if a logline contains this, it is considered bad, the rest is good
      --generic-negative <GENERIC_NEGATIVE>
          generic parser negative - if a logline contains this, it is considered good, the rest is bad
      --invalid-http-statuses <INVALID_HTTP_STATUSES>
          invalid http statuses (for CLF and JSON logs). Coma separated list, accepts ranges with XX [default: 400,401,402,403]
  -h, --help
          Print help
  -V, --version
          Print version
```
