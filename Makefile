# Each command is run in a separate sub-shell.
# Prefix commands with "@" to suppress command echo.
# Example: https://sohlich.github.io/post/go_makefile/

all: test build

# Setup local Git hooks.
githooks:
	./scripts/githooks.sh

# Generate Go docs.
docs:
	./scripts/docs.sh

# Serve HTML documentation using pkgsite.
docserve:
	./scripts/docserve.sh

# Run tests and generate HTML coverage report at [.coverage.html].
test:
	./scripts/test.sh

# Lint the code.
lint:
	./scripts/lint.sh

# Run SAST.
sast:
	./scripts/sast.sh

# Check the modules.
modcheck:
	./scripts/modcheck.sh

# Build single target binary using goreleaser config.
build:
	./scripts/build.sh

# Local installation of existing built executable.
_build_install:
	./scripts/install.sh

# Local build and installation of executable.
install: build _build_install

# Build point-in-time snapshot release.
snapshot:
	./scripts/snapshot.sh

# Create a release for supported platforms.
release:
	./scripts/release.sh

# Login to the Docker registry.
docker_login:
	./scripts/docker_login.sh
