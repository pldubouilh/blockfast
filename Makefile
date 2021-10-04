build:
	cargo build
	cargo clippy
	cargo fmt

run:
	cargo run -- -s=/tmp/sshdtest -c=/tmp/clftest

watch:
	ls src/*.rs | entr -rc -- make run

test:
	cargo test

watch-test:
	ls src/*.rs | entr -rc -- make test

release:
	cargo build --target x86_64-unknown-linux-musl --release

ci: test
	cargo fmt --all -- --check
	cargo clippy -- -D warnings