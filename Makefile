build::
	cargo build
	cargo clippy
	cargo fmt

run:: build
	sudo target/debug/blockfast -s=/tmp/sshdtest -c=/tmp/clftest

watch::
	ls src/*.rs | entr -rc -- make run

test::
	cargo test

watch-test::
	ls src/*.rs | entr -rc -- make test

release::
	cargo build --target x86_64-unknown-linux-musl --release

ci:: test
	cargo fmt --all -- --check
	cargo clippy -- -D warnings

hit-sshd-bad::
	echo "Sep 26 06:26:14 livecompute sshd[23292]: pam_unix(sshd:auth): authentication failure; logname= u =0 tty=ssh ruser= rhost=5.101.107.191" >> /tmp/sshdtest

hit-clftest-bad::
	echo "8.8.8.8 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 200 923" >> /tmp/clftest