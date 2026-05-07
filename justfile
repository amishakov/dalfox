alias b := build
alias d := dev
alias t := test
alias vc := version-check
alias vu := version-update

# List available tasks.
default:
    @just --list

# Build release binary.
[group('build')]
build:
    cargo build --release

# Build debug binary.
[group('build')]
dev:
    cargo build

# Update Nix flake lock.
[group('build')]
nix-update:
    nix flake update

#[group('development')]
#fix:
#    cargo fmt
#    cargo clippy --fix --allow-dirty

# Report dalfox version across Cargo.toml, Cargo.lock, flake.nix, snap.
[group('release')]
version-check:
    crystal run scripts/version_check.cr

# Bump dalfox version in lockstep across all version-bearing files.
[group('release')]
version-update:
    crystal run scripts/version_update.cr

# Run unit tests.
[group('test')]
test:
    cargo test

# Run all tests including ignored ones.
[group('test')]
test_all:
    cargo test -- --include-ignored
