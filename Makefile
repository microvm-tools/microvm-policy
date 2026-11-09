GO                 ?= go
GOLANGCI_LINT      ?= golangci-lint
# The Go module is the proxy; every Go target runs inside it.
GO_DIR             ?= proxy
COVERPROFILE       ?= coverage.out
COVERAGE_THRESHOLD ?= 80

.PHONY: all build test cover fmt lint check hooks diff-closures release release-notes release-tag release-tag-preview clean

all: build

# Points git at the version-controlled hooks in .githooks (pre-commit runs the
# linter). Per-clone, so each contributor runs it once.
hooks:
	git config core.hooksPath .githooks
	@echo "installed git hooks from .githooks"

build:
	cd $(GO_DIR) && $(GO) build -o /dev/null ./...

# Runs the proxy's unit tests with coverage and fails if total coverage drops
# below COVERAGE_THRESHOLD. What unit tests cannot reach -- main(), and the
# proxy against real VMs -- is covered by the egress-integration nixosTest
# (`make check`).
test:
	cd $(GO_DIR) && $(GO) test -race -coverprofile=$(COVERPROFILE) ./...
	@total=$$(cd $(GO_DIR) && $(GO) tool cover -func=$(COVERPROFILE) | awk '/^total:/ {gsub(/%/,"",$$NF); print $$NF}'); \
	printf "Total coverage: %s%% (threshold: %d%%)\n" "$$total" "$(COVERAGE_THRESHOLD)"; \
	if awk "BEGIN{exit !($$total < $(COVERAGE_THRESHOLD))}"; then \
		printf "FAIL: coverage %s%% is below %d%%\n" "$$total" "$(COVERAGE_THRESHOLD)"; \
		exit 1; \
	fi

# Opens the per-line coverage report from the last `make test` in a browser.
cover: test
	cd $(GO_DIR) && $(GO) tool cover -html=$(COVERPROFILE)

# Applies the formatters declared in .golangci.yaml (gofumpt).
fmt:
	cd $(GO_DIR) && $(GOLANGCI_LINT) fmt ./...

lint:
	cd $(GO_DIR) && $(GOLANGCI_LINT) run ./...

# Every flake check: the proxy package (its build runs the Go tests), the
# egress-report fixture test, and the 4-node egress-integration nixosTest
# (needs KVM).
check:
	nix flake check

# What did the last `nix flake update` actually change? Rebuilds an attribute
# against the nixpkgs revision committed at HEAD and diffs the two closures --
# the lock diff alone only says a revision moved, not whether the move reaches
# anything we build. Evaluation-only unless the derivations differ.
#
# The Go toolchain is not one of nixpkgs' packages, so roll back its input
# instead with ARGS='-i go-overlay'. Other examples:
# ARGS='-a packages.x86_64-linux.egress-report'.
diff-closures:
	@scripts/diff-closures.sh $(ARGS)

# Publishes the GitHub release for the current tag. Invoked by CI on tag push;
# needs GITHUB_TOKEN and a clean tagged tree. Re-runs the gates first so a
# local `make release` matches what CI enforces.
# There are no release archives: consumers take this repo as a flake input,
# so the release is the tag plus its notes. The notes come from git-cliff
# (see cliff.toml), which owns the whole body -- header, changelog, footer.
release: lint test build
	@tag="$$(git describe --tags --exact-match HEAD)" || { \
		echo "HEAD is not tagged — run \`make release-tag\` first." >&2; exit 1; }; \
	notes="$$(mktemp)"; \
	git-cliff --latest > "$$notes" || { rm -f "$$notes"; exit 1; }; \
	gh release create "$$tag" --verify-tag --title "$$tag" --notes-file "$$notes"; \
	rc=$$?; rm -f "$$notes"; exit $$rc

# Preview the release notes for the current tag without releasing anything.
release-notes:
	@git-cliff --latest

# Preview the version `release-tag` would cut, without touching anything.
# gsemver derives it from the conventional-commit history since the last tag,
# and it fetches, so this needs network access to the remote.
release-tag-preview:
	@v="$$(gsemver bump)"; \
	test -n "$$v" || { echo "gsemver produced no version — is the remote reachable?" >&2; exit 1; }; \
	printf "next tag: v%s\n" "$$v"

# Computes the next version from conventional-commit history, writes it into
# ./VERSION (the source of truth the flake reads), commits that as the release
# commit, tags it, and pushes branch + tag -- which triggers the release job.
# Because the version is committed *before* the tag, the tagged tree's Nix
# build and the tag report the same version. The chore commit is a non-bumping
# type, so it does not skew the next gsemver bump.
# Override the version with `make release-tag VERSION=1.2.3`.
#
# The tag is signed with -s. tag.forcesignannotated does NOT achieve this: git
# gives an explicit --annotate/-a precedence over that config, so `git tag -a`
# produces an unsigned tag however the config is set.
release-tag:
	$(eval VERSION ?= $(shell gsemver bump))
	@test -n "$(VERSION)" || { \
		echo "gsemver produced no version — refusing to tag." >&2; \
		echo "make hides a failing command inside its shell function, and an empty" >&2; \
		echo "version would tag and push a ref literally named v. Check the remote" >&2; \
		echo "is reachable and gsemver is on PATH." >&2; \
		exit 1; \
	}
	@git config --get user.signingkey >/dev/null || { \
		echo "user.signingkey is unset — the signed tag would fail after the" >&2; \
		echo "release commit was already made, leaving a half-cut release." >&2; \
		exit 1; \
	}
	@printf '%s\n' "$(VERSION)" > VERSION
	git add VERSION
	git commit -m "chore: release v$(VERSION)" VERSION
	git tag -s "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin HEAD "v$(VERSION)"

clean:
	rm -rf result result-* $(GO_DIR)/$(COVERPROFILE)
