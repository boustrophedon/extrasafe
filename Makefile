build:
	cargo build --all-features

# Run all tests and examples
test:
	cargo test --tests --examples --all-features
	cargo run --all-features --example isolate_test
	cargo run --all-features --example ipc_server_with_database

# Run all tests with and without all features
test-ci:
	cargo test --target=$(TARGET_TRIPLE) --tests --examples --all-features
	cargo test --target=$(TARGET_TRIPLE) --tests --examples --no-default-features
	cargo run --target=$(TARGET_TRIPLE) --all-features --example isolate_test
	cargo run --target=$(TARGET_TRIPLE) --all-features --example ipc_server_with_database

# Run clippy
lint:
	cargo clippy --no-deps --all-targets --all-features -- -W clippy::pedantic \
		-A clippy::let-unit-value \
		-A clippy::wildcard-imports \
		-A clippy::module-name-repetitions \
		-A clippy::uninlined-format-args

# Generate docs
doc:
	RUSTDOCFLAGS="-Dwarnings" cargo doc --no-deps

do-cov:
	cargo llvm-cov clean --workspace
	cargo llvm-cov --no-report --tests --examples --all-targets --all-features --workspace
	cargo llvm-cov --no-report --all-features run --example isolate_test
	cargo llvm-cov --no-report --all-features run --example ipc_server_with_database

# Compute test coverage for CI with llvm-cov
coverage-ci: do-cov
	cargo llvm-cov report --lcov --output-path lcov.info

# Compute test coverage with HTML output
coverage: do-cov
	cargo llvm-cov report --html
