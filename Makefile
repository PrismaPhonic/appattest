.PHONY: cargo-fix 

cargo-fix:
	@echo "Running clippy fix"
	@cargo clippy --locked --no-deps --fix
	@echo "Running cargo fmt"
	@cargo +nightly fmt --all -- --emit files
