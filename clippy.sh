#!/bin/bash
cargo clippy --no-deps --all-targets --all-features -- -W clippy::pedantic \
	-A clippy::let-unit-value \
	-A clippy::wildcard-imports \
	-A clippy::module-name-repetitions
