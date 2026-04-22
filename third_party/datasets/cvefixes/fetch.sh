#!/usr/bin/env bash
# Download CVEfixes from Zenodo and extract CVEfixes.db alongside this script.
#
# CVEfixes is released under CC BY 4.0 by Bhandari, Naseer, and Moonen (2021).
# See README.md in this directory for attribution and citation details.
set -euo pipefail

VERSION="${1:-v1.0.7}"
case "$VERSION" in
  v1.0.7) ZENODO_ID="7029359";  ZIP_SIZE="~3.9 GB" ;;
  v1.0.8) ZENODO_ID="13118970"; ZIP_SIZE="~12 GB"  ;;
  *)
    echo "fetch.sh: unknown version '$VERSION' (supported: v1.0.7, v1.0.8)" >&2
    exit 1
    ;;
esac

cd "$(dirname "$0")"

ZIP="CVEfixes_${VERSION}.zip"
URL="https://zenodo.org/records/${ZENODO_ID}/files/${ZIP}?download=1"

if [[ -f CVEfixes.db ]]; then
  echo "fetch.sh: CVEfixes.db already present here, nothing to do."
  echo "  Delete it manually and re-run if you want to refresh."
  exit 0
fi

echo "Downloading CVEfixes ${VERSION} (${ZIP_SIZE}) from Zenodo..."
echo "  Record: https://zenodo.org/records/${ZENODO_ID}"
echo "  URL:    ${URL}"
echo
curl -L --fail -C - -o "$ZIP" "$URL"

echo
echo "Extracting CVEfixes.db..."
unzip -o "$ZIP" "CVEfixes_${VERSION}/Data/CVEfixes.db"
mv "CVEfixes_${VERSION}/Data/CVEfixes.db" ./CVEfixes.db
rmdir "CVEfixes_${VERSION}/Data" "CVEfixes_${VERSION}" 2>/dev/null || true

echo
echo "Done. CVEfixes.db placed at: $(pwd)/CVEfixes.db"
echo "License: CC BY 4.0 — see README.md for attribution requirements."
echo
echo "The downloaded zip ($ZIP) is kept for resume on re-run; delete to reclaim disk."
