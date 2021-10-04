# blockfast

block ssh and http scanners fast

features:
  - generic SSH log parser
  - generic Common Log Format parser (apache logs, caddy logs, etc...)
  - sane defaults
  - fast ip ban with `ipset`
  - libmusl static release builds, no libc dependency
  - lighter alternative to fail2ban

Todo: more granular CLI args to filter HTTP Status codes (e.g. 5 401 leads to a block, but 30 404 before a block) ?
