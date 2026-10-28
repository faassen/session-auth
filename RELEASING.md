# Releasing

Make sure the changes of the release are listed in `CHANGES.md` under the
`## Unreleased` heading, then run:

```
cargo xtask release <level>
```

where `<level>` is `major`, `minor` or `patch`.

For the first release, leave out the level to release the version that is
already in `Cargo.toml`.
