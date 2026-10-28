#!/bin/sh
# Install the Kavach pre-commit hook into a git repository.
# Usage: scripts/install-hook.sh [path/to/repo]   (defaults to this repo)
set -eu

repo="${1:-$(git rev-parse --show-toplevel)}"
hooks_dir="$(git -C "$repo" rev-parse --absolute-git-dir)/hooks"
hook="$hooks_dir/pre-commit"

if [ -e "$hook" ] && ! grep -qE "Kavach|ZeroDay Sentinel" "$hook"; then  # ours, under either name
  echo "A different pre-commit hook already exists at $hook; not overwriting." >&2
  exit 1
fi

mkdir -p "$hooks_dir"
cat > "$hook" <<'EOF'
#!/bin/sh
# Kavach pre-commit hook. Bypass once with: SENTINEL_SKIP=1 git commit ...
if command -v sentinel-hook >/dev/null 2>&1; then
  exec sentinel-hook
fi
echo "sentinel: sentinel-hook not found on PATH (pip install -e backend); commit not checked." >&2
exit 0
EOF
chmod +x "$hook"
echo "Installed pre-commit hook at $hook"
