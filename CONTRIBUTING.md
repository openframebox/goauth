# Contributing to goauth

Thanks for your interest in contributing! This document outlines how to set up your environment, run the project, and propose changes.

## Getting Started

- Go 1.21+ recommended.
- Clone the repo and tidy modules:

```
git clone https://github.com/openframebox/goauth.git
cd goauth
go mod tidy
```

## Development

- Build all packages: `go build ./...`
- Run tests: `go test ./...`
- Run the example app: `go run ./example`

We use plain `gofmt` for formatting. Please format before submitting:

```
gofmt -w .
```

Optional local checks:

- Vet: `go vet ./...`
- Staticcheck (if installed): `staticcheck ./...`

## Project Structure

- `goauth.go`: orchestrator and public entry points
- `interface.go`: core interfaces and function types
- `entity.go`: value objects (AuthParams, Token, User)
- `jwt_strategy.go`, `local_strategy.go`: built-in strategies
- `token.go`: DefaultTokenIssuer (JWT access + UUID refresh)
- `errors.go`, `http_errors.go`: typed errors and HTTP mappings
- `example/`: runnable demo

## Design Guidelines

- Keep surface area small and composable; prefer hooks over monoliths.
- Use typed errors (`CredentialError`, `TokenError`, `ConfigError`, `NotFoundError`, `InternalError`).
- Return sentinel errors where it helps callers (e.g., `ErrMissingToken`).
- Avoid panics; validate inputs early and return typed errors.
- Maintain backward compatibility for public APIs when possible.

## Adding Features

1. Open an issue describing the problem/use case.
2. Propose API changes (interfaces, methods, hooks) with examples.
3. Keep implementations minimal; avoid adding heavy dependencies.
4. Include docs updates in `README.md` and, if needed, example changes.

## Pull Requests

- Small, focused PRs are easier to review.
- Include tests when fixing bugs or adding features.
- Ensure `go build ./...` and `go test ./...` pass.
- Describe the change, rationale, and any breaking aspects.

## Commit Messages

- Use clear, imperative messages (e.g., "add jwt strategy option for ...").
- Reference issues when applicable (e.g., "fixes #123").

## Code of Conduct

Be respectful and inclusive. Harassment or discrimination is not tolerated.

## Security

If you discover a security issue, please do not open a public issue. Email the maintainers or the organization’s security contact instead. We will coordinate a fix and disclosure.

## License

By contributing, you agree that your contributions will be licensed under the MIT License (see LICENSE).

