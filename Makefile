build:
	cargo build --feature=landlock

# Run all tests and examples
test:
	cargo test --tests --examples --all-features

# Run all tests with and without all features
test-ci:
	cargo test --target=$(TARGET_TRIPLE) --tests --examples --feature=landlock
	cargo test --target=$(TARGET_TRIPLE) --tests --examples --no-default-features

# Run clippy
lint:
	cargo clippy --no-deps --all-targets --feature=landlock -- -W clippy::pedantic \
		-A clippy::let-unit-value \
		-A clippy::wildcard-imports \
		-A clippy::module-name-repetitions \
		-A clippy::uninlined-format-args

# Generate docs
doc:
	RUSTDOCFLAGS="-Dwarnings" cargo doc --no-deps

# Compute test coverage for CI with llvm-cov
coverage-ci:
	cargo llvm-cov --tests --examples --all-targets --feature=landlock --workspace --lcov --output-path lcov.info

# Compute test coverage with HTML output
coverage:
	cargo llvm-cov --tests --examples --all-targets --feature=landlock --workspace --html
