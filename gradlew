#!/usr/bin/env sh
set -eu

GRADLE_VERSION=8.14.3
BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GRADLE_HOME="$BASE_DIR/.gradle/bootstrap/gradle-$GRADLE_VERSION"
GRADLE_BIN="$GRADLE_HOME/bin/gradle"
GRADLE_ZIP="$BASE_DIR/.gradle/bootstrap/gradle-$GRADLE_VERSION-bin.zip"

if [ ! -x "$GRADLE_BIN" ]; then
  echo "Bootstrapping Gradle $GRADLE_VERSION..."
  mkdir -p "$BASE_DIR/.gradle/bootstrap"
  if command -v curl >/dev/null 2>&1; then
    curl -L "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip" -o "$GRADLE_ZIP"
  elif command -v wget >/dev/null 2>&1; then
    wget "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip" -O "$GRADLE_ZIP"
  else
    echo "curl or wget is required to bootstrap Gradle." >&2
    exit 1
  fi
  unzip -q "$GRADLE_ZIP" -d "$BASE_DIR/.gradle/bootstrap"
fi

exec "$GRADLE_BIN" "$@"
