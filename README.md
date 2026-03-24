# capsule-service

Go backend for [GemCities](https://gemcities.com) — a free Gemini capsule hosting service.

Handles account registration, authentication, file management, storage enforcement, and the editor API. Runs as a single compiled binary managed by systemd.

## Documentation

Full project documentation lives in [`docs/`](docs/):

| File | Contents |
|------|----------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Technical stack, infrastructure, API surface, database schema |
| [AUTH.md](docs/AUTH.md) | Registration flow, authentication, session management |
| [SECURITY.md](docs/SECURITY.md) | File isolation, path traversal protection, rate limiting |
| [EDITOR.md](docs/EDITOR.md) | Web editor UI specification |
| [PHILOSOPHY.md](docs/PHILOSOPHY.md) | Core commitments and non-negotiables |
| [SUSTAINABILITY.md](docs/SUSTAINABILITY.md) | Cost model, donation approach, operator continuity |
| [LAUNCH.md](docs/LAUNCH.md) | Four-phase launch plan and pre-launch checklist |
| [NON-FEATURES.md](docs/NON-FEATURES.md) | Permanent list of things that will never be built |
| [RISK.md](docs/RISK.md) | Risk register with mitigations |
| [GEMTEXT.md](docs/GEMTEXT.md) | Gemtext format reference |

## Related Repos

- [capsule-editor](https://github.com/njb1966/capsule-editor) — Web editor frontend (vanilla HTML/CSS/JS)
- [capsule-deploy](https://github.com/njb1966/capsule-deploy) — Config templates, systemd units, setup scripts

## License

AGPL-3.0 — see [LICENSE](LICENSE)