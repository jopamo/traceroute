# Repository Guidelines

## Project Structure & Module Organization

- `traceroute/` contains the main C implementation, protocol modules (`mod-*.c`), and the man page `traceroute.8`.
- `libsupp/` provides support utilities (e.g., CLI parsing in `clif.c`).
- `include/` holds public headers used across modules.
- `build/` is the Meson build output directory (generated).

## Build, Test, and Development Commands

- `meson setup build` — configure the project into `build/` (run once or after clean).
- `meson compile -C build` — build the binary.
- `sudo meson install -C build` — install system-wide (optional).
- `./build/traceroute/traceroute --help` — run the local build (path may vary by Meson version).

## Coding Style & Naming Conventions

- Language: C (GNU11). Follow `.clang-format` (Chromium base, 4-space indents, 120-column limit).
- File naming: `mod-<proto>.c` for traceroute modules (e.g., `mod-udp.c`).
- Prefer descriptive, lower_snake_case function names as used throughout the codebase.
- If you change formatting, run `clang-format` with the repo’s config.

## Testing Guidelines

- No automated test suite is currently present in this repo.
- Validate changes by building and running a few traceroutes (IPv4/IPv6, different modules).

## Commit & Pull Request Guidelines

- Commit messages commonly use a conventional style such as `type(scope): summary` (e.g., `refactor(build): ...`) or `path: summary` (e.g., `traceroute/traceroute.c: ...`).
- Keep commits focused; explain the “why” in the body when behavior changes.
- PRs should include a short description, build/test commands run, and any relevant context or issue links.
