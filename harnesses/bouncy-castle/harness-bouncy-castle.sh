#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec /opt/homebrew/opt/openjdk/bin/java -cp "$DIR:$DIR/bcprov.jar" CrucibleHarness
