BLOCKFAST_VERS := $(shell date '+%Y-%m-%d') / $(shell git rev-parse --short HEAD)
export BLOCKFAST_VERS

build::
	echo $(BLOCKFAST_VERS)
	cargo build
	cargo clippy --all
	cargo fmt --all

run::
	touch /tmp/sshdtest
	touch /tmp/clftest
	touch /tmp/jsontest
	touch /tmp/generictest
	cargo build
	sudo target/debug/blockfast -v -s=/tmp/sshdtest -c=/tmp/clftest -j=/tmp/jsontest --generic-logpath=/tmp/generictest --generic-ip='from ([0-9a-fA-F:.]+) port' --generic-positive='Failed password'

ci:: test
	cargo fmt --all -- --check
	cargo clippy -- -D warnings

build-all::
	mkdir -p builds
	rustc --version > builds/buildout
	cross build --release --target x86_64-unknown-linux-musl
	cross build --release --target aarch64-unknown-linux-musl
	cross build --release --target armv7-unknown-linux-musleabihf
	cp target/x86_64-unknown-linux-musl/release/blockfast builds/blockfast-x86_64-linux
	cp target/aarch64-unknown-linux-musl/release/blockfast builds/blockfast-aarch64-linux
	cp target/armv7-unknown-linux-musleabihf/release/blockfast builds/blockfast-arm7-linux
	sha256sum builds/* >> builds/buildout

watch::
	ls src/*.rs | entr -rc -- make run

test::
	cargo test

release::
	cargo build --target x86_64-unknown-linux-musl --release

hit-sshd::
	echo "Sep 26 06:25:32 livecompute sshd[23254]: Invalid user neal from 9.124.36.195" >> /tmp/sshdtest

ok-sshd::
	echo "Sep 26 06:25:19 livecompute sshd[23246]: successful login 8.124.36.195 port 41883 ssh2" >> /tmp/sshdtest

hit-generic::
	echo "Sep 26 06:25:19 livecompute sshd[23246]: Failed password for root from 179.124.36.195 port 41883 ssh2"  >> /tmp/generictest

ok-generic::
	echo "Sep 26 06:25:19 livecompute sshd[23246]: Successful login for root from 179.124.36.195 port 41883 ssh2"  >> /tmp/generictest

hit-clf::
	echo "1.124.36.195 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 401 923" >> /tmp/clftest

ok-clf::
	echo "2.124.36.195 - p [25/Sep/2021:13:49:56 +0200] \"POST /some/rpc HTTP/2.0\" 200 23012" >> /tmp/clftest

hit-json::
	echo "{\"request\":{\"remote_ip\":\"1.124.36.19\"}, \"status\": 400}" >> /tmp/jsontest

ok-json::
	echo "{\"request\":{\"remote_ip\":\"2.124.36.19\"}, \"status\": 200}" >> /tmp/jsontest

