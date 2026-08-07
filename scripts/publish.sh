#!/usr/bin/env bash
# Builds Oko for amd64 and arm64 and pushes it to Docker Hub as a single manifest list.
#
# Multi-architecture is not optional here: an image built on an Apple Silicon Mac is arm64-only, and
# `docker run` on an ordinary x86_64 server fails outright with "no matching manifest".
#
#   ./scripts/publish.sh              # version from Directory.Build.props
#   ./scripts/publish.sh 0.2.0        # explicit version
#   ./scripts/publish.sh --dry-run    # print what would happen, push nothing

set -euo pipefail

IMAGE="${OKO_IMAGE:-davidkarlas/oko}"
PLATFORMS="${OKO_PLATFORMS:-linux/amd64,linux/arm64}"
BUILDER="oko-multiarch"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DRY_RUN="no"
ALLOW_DIRTY="no"
PUSH_LATEST="yes"
VERSION=""

die() { printf 'publish: %s\n' "$*" >&2; exit 1; }
note() { printf '\033[1m==>\033[0m %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN="yes"; shift ;;
        --allow-dirty) ALLOW_DIRTY="yes"; shift ;;
        --no-latest) PUSH_LATEST="no"; shift ;;
        -h|--help)
            # Print the header comment block, stopping at the first line that is not a comment, so the
            # help text cannot drift out of sync with a fixed line range.
            awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "${BASH_SOURCE[0]}"
            exit 0 ;;
        -*) die "unknown option '$1'" ;;
        *) VERSION="$1"; shift ;;
    esac
done

cd "$REPO_ROOT"

# ---- version -----------------------------------------------------------------------------------------
if [ -z "$VERSION" ]; then
    VERSION=$(sed -n 's/.*<OkoVersion>\(.*\)<\/OkoVersion>.*/\1/p' Directory.Build.props | head -1)
    [ -n "$VERSION" ] || die "could not read <OkoVersion> from Directory.Build.props"
fi

case "$VERSION" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) die "version '$VERSION' does not look like x.y.z" ;;
esac

# ---- preflight ---------------------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker not found"
docker buildx version >/dev/null 2>&1 || die "docker buildx not available"

REVISION=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

if [ "$ALLOW_DIRTY" = "no" ] && [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    die "working tree is dirty; commit first so the published image matches a real commit (or --allow-dirty)"
fi

# A published tag should be reproducible from a commit someone else can fetch.
if [ "$ALLOW_DIRTY" = "no" ] && ! git merge-base --is-ancestor HEAD "@{upstream}" 2>/dev/null; then
    printf 'publish: warning: HEAD (%s) is not pushed to the upstream branch yet\n' "$REVISION" >&2
fi

if [ "$DRY_RUN" = "no" ] && ! grep -q '"auths"' "${DOCKER_CONFIG:-$HOME/.docker}/config.json" 2>/dev/null; then
    die "not logged in to a registry. Run 'docker login' first (it prompts interactively)."
fi

# ---- verify before publishing -------------------------------------------------------------------------
if [ "${OKO_SKIP_TESTS:-no}" != "yes" ]; then
    note "Running the test suite (set OKO_SKIP_TESTS=yes to skip)"
    dotnet test Oko.slnx --nologo
fi

# ---- builder ------------------------------------------------------------------------------------------
# The default "docker" driver cannot emit a multi-platform manifest; a docker-container builder can.
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
    note "Creating buildx builder '$BUILDER'"
    [ "$DRY_RUN" = "yes" ] || docker buildx create --name "$BUILDER" --driver docker-container --bootstrap >/dev/null
fi

TAGS=(-t "$IMAGE:$VERSION")
[ "$PUSH_LATEST" = "yes" ] && TAGS+=(-t "$IMAGE:latest")

note "Image      : $IMAGE"
note "Version    : $VERSION  (revision $REVISION)"
note "Platforms  : $PLATFORMS"
note "Tags       : $VERSION$([ "$PUSH_LATEST" = "yes" ] && echo ', latest')"

BUILD_ARGS=(
    buildx build
    --builder "$BUILDER"
    --platform "$PLATFORMS"
    --build-arg "OKO_VERSION=$VERSION"
    --build-arg "OKO_REVISION=$REVISION"
    "${TAGS[@]}"
    .
)

if [ "$DRY_RUN" = "yes" ]; then
    note "Dry run — would execute:"
    printf '  docker %s --push\n' "${BUILD_ARGS[*]}"
    note "Building both platforms without pushing, to prove the cross-compile works"
    docker "${BUILD_ARGS[@]}" --output type=cacheonly
    note "Dry run complete. Nothing was pushed."
    exit 0
fi

note "Building and pushing"
docker "${BUILD_ARGS[@]}" --push

# ---- verify what landed -------------------------------------------------------------------------------
note "Verifying the published manifest"

# Parse the human-readable output rather than --raw JSON: the raw index is pretty-printed, so matching
# on "architecture":"amd64" fails on the space after the colon and reports a false negative.
MANIFEST=$(docker buildx imagetools inspect "$IMAGE:$VERSION")
printf '%s\n' "$MANIFEST"

for platform in ${PLATFORMS//,/ }; do
    if printf '%s\n' "$MANIFEST" | grep -qE "Platform:[[:space:]]+${platform}([[:space:]]|\$)"; then
        printf '    %s present\n' "$platform"
    else
        die "$platform is missing from the published manifest"
    fi
done

# buildx also attaches provenance attestations, which appear as extra unknown/unknown entries. They are
# expected; only the real platforms above are checked.
note "Done: docker pull $IMAGE:$VERSION"
