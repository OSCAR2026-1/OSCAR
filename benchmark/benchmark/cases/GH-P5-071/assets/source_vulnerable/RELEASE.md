# Release Workflow

## Quick Start

### Automated Release (Recommended)

```bash
# 1. Add changeset
pnpm changeset:add

# 2. Release (auto version, commit, tag, and push)
pnpm release
```

The `pnpm release` command automatically:
- Updates version and CHANGELOG
- Commits changes
- Creates and pushes git tag
- Triggers OIDC publish via GitHub Actions

### Manual Release

```bash
# 1. Add changeset
pnpm changeset add

# 2. Update version
pnpm changeset version

# 3. Commit and push
git add .
git commit -m "chore: version packages"
git push origin main

# 4. Create and push tag
git tag v$(node -p "require('./package.json').version")
git push origin v$(node -p "require('./package.json').version")
```

## Changeset Types

- **patch** (1.0.x): Bug fixes, minor improvements
- **minor** (1.x.0): New features, backward compatible
- **major** (x.0.0): Breaking changes

## Verification

After release, verify:
- [GitHub Actions](https://github.com/Orchardxyz/mammoth-mcp/actions) - workflow success
- [npm package](https://www.npmjs.com/package/mammoth-mcp) - new version published
- [GitHub Releases](https://github.com/Orchardxyz/mammoth-mcp/releases) - release created

## Troubleshooting

**If tag exists:**
```bash
git tag -d v1.0.x
git push origin --delete v1.0.x
```

**If publish fails:** Check [Actions logs](https://github.com/Orchardxyz/mammoth-mcp/actions) for details.

## Technical Notes

- Uses npm OIDC trusted publishing (no token management required)
- npm CLI auto-upgraded to latest (requires 11.5.1+)
- Provenance disabled via `NPM_CONFIG_PROVENANCE=false`
