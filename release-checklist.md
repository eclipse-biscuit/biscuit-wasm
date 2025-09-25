# Release checklist

biscuit-wasm is part of the [Eclipse Biscuit](https://projects.eclipse.org/projects/technology.biscuit) project and as such needs to conform the eclipse project management guidelines.

Eclipse projects can only be released within the validity period of a release review (they last for 1 year).

## Pre-release

- make sure `README.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md` are present and up-to-date
- make sure `LICENSE` is present and that all source files are properly annotated with copyright and license information
- make sure dependency license information is correctly vetted:

```bash
 cargo tree -e normal --prefix none --no-dedupe | sort -u | grep -v '^[[:space:]]*$'  | grep -v biscuit  | sed -E 's|([^ ]+) v([^ ]+).*|crate/cratesio/-/\1/\2|' | java -jar org.eclipse.dash.licenses-1.1.0.jar - 
```
(you’ll need to download the [eclipse dash licenses jar](repo.eclipse.org/content/repositories/dash-licenses/org/eclipse/dash/org.eclipse.dash.licenses/))

This step should be automated at some point.

Note: the js library does not have any dependency so this step is only required for rust dependencies.

## Requesting a release review

If the most recent release review is outdated, we will need to start a new one on the [project governance page](https://projects.eclipse.org/projects/technology.biscuit/governance).

## Actually releasing stuff

- update the version in `Cargo.toml`;
- update `CHANGELOG.md` (ideally, try to update it in each PR, in an _unreleased_ section to make things easier);
- merge the PR;
- tag the new `main` commit;
- run `npm publish`.
