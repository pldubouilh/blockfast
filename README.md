# blockfast

Block internets scanners fast 🍶

Features:
  - SSH log parser
  - Common Log Format parser (apache logs, etc...)
  - JSON log parser (caddy logs)
  - Generic log parser
  - Sane defaults
  - Fast ip ban with `ipset`
  - Static release builds, no libc dependency
  - Lighter alternative to fail2ban

## example
```txt
$ ./blockfast -s=/var/log/auth.log -j=/caddy/logs
1737927469 - starting with sshd parsing at "/tmp/sshdtest"
1737927469 - starting with json parsing at "/tmp/jsontest"
1737927469 - jail setup, allowance 5, time 21600s
1737927477 - sshd logged offence for 9.124.36.195
1737927478 - sshd logged offence for 9.124.36.195
1737927479 - sshd logged offence for 9.124.36.195
1737927479 - sshd logged offence for 9.124.36.195
1737927480 - sshd logged offence for 9.124.36.195
1737927480 - sshd jailtime for 9.124.36.195
```

## build
see `Makefile`

## usage
```txt
$ target/debug/blockfast
Blockfast - block internets scanners fast 🍶
Author: pierre dubouilh <pldubouilh@gmail.com>

Blockfast reads logs from various sources and blocks the offending IPs using iptables and ipset.
It supports logs from sshd, Common-Log-Format (Apache, etc..), JSON (Caddy) and a generic logs parser.

Example:
    # block invalid sshd attempts & invalid http statuses from caddy
    ./blockfast -s=/var/log/auth.log -j=/caddy/logs

    # generic log parser example with a log text to flag, and a regex to parse the offending IP.
    ./blockfast --generic-logpath=/tmp/generictest --generic-positive='Failed password' --generic-ip='from ([0-9a-fA-F:.]+) port'

Usage: blockfast [OPTIONS]
Usage: blockfast [OPTIONS]

Options:
      --jailtime <JAILTIME>
          jail time (seconds) [default: 21600]
      --allowance <ALLOWANCE>
          how many offences allowed (max 255) [default: 5]
  -v, --verbose
          log all offences
  -s, --sshd-logpath <SSHD_LOGPATH>
          path of sshd logfile
  -c, --clf-logpath <CLF_LOGPATH>
          path of Common-Log-Format logfile (Apache, etc..)
  -j, --json-logpath <JSON_LOGPATH>
          path of JSON HTTP logfile (Caddy)
      --generic-logpath <GENERIC_LOGPATH>
          generic parser log file path
      --generic-ip <GENERIC_IP>
          generic parser ip regex
      --generic-positive <GENERIC_POSITIVE>
          generic parser positive - if a logline contains this, it is considered bad, the rest is good
      --generic-negative <GENERIC_NEGATIVE>
          generic parser negative - if a logline contains this, it is considered good, the rest is bad
      --valid-http-statuses <VALID_HTTP_STATUSES>
          valid http statuses (for CLF and JSON logs) [default: 200 101]
  -h, --help
          Print help
  -V, --version
          Print version
```
