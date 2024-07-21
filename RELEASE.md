# Releases

## New Releases

New releases require a semver tag on the default branch (`main`).

```
# Example semver tag without suffix.
git tag "v1.0.2"; git push --tags

# Example semver tag, with suffix.
git tag "v1.0.2-alpha03"; git push --tags
```

The `release` Github Actions workflow will be triggered, running GoReleaser.
A new binary will be built, a Docker image and documentation with be pushed.

Pull the latest image: `docker pull divergentcodes/jwt-block:latest`

View the latest Docker release: https://hub.docker.com/r/divergentcodes/jwt-block


## Changelog Updates

GoReleaser auto-generates Changelog updates.  Changelog generation follows [Conventional Commits](https://www.conventionalcommits.org/en)

To be included in a changelog, PR titles must be one of these prefixes:
- `feat:` - New features.
- `enhance:` - Enhancements.
- `fix:` - Bug fixes.


## Links

- Binary downloads: https://github.com/DivergentCodes/jwt-block/releases

- Docker images: https://hub.docker.com/r/divergentcodes/jwt-block

- JWT Block docs: https://pkg.go.dev/github.com/divergentcodes/jwt-block


