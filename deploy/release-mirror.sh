#!/usr/bin/env bash
# release-mirror.sh — mirror the latest GitHub release assets onto this box so
# the app's self-update still works when github.com is throttled/blocked for
# the user. The panel serves the dir publicly at /releases/ (see the
# -releases-dir flag), so the mirror URL is https://panel.mergescribe.dev/releases/.
#
# Layout in /var/www/kal2-releases:
#   latest.json         {"tag":"v1.2.0","assets":[{"name":..,"url":"/releases/v1.2.0/<file>"}]}
#   <tag>/<asset files>
#
# Cron on the US box (every 20 min is plenty — releases are rare):
#   */20 * * * * /etc/kal2/release-mirror.sh >/dev/null 2>&1
set -u

REPO=${MIRROR_REPO:-Frtertaer/milkyvpn}
DIR=${MIRROR_DIR:-/var/www/kal2-releases}
mkdir -p "$DIR"

json=$(curl -sf -m 15 -H 'User-Agent: milkyvpn-mirror' \
  "https://api.github.com/repos/$REPO/releases/latest") || exit 0

python3 - "$json" <<'PY' > /tmp/mirror-meta
import json, sys
r = json.loads(sys.argv[1])
tag = r.get("tag_name", "")
assets = [{"name": a["name"], "dl": a["browser_download_url"]}
          for a in r.get("assets", [])]
print(json.dumps({"tag": tag, "assets": assets}))
PY

tag=$(python3 -c "import json,sys; print(json.load(open('/tmp/mirror-meta'))['tag'])")
[ -n "$tag" ] || exit 0

mkdir -p "$DIR/$tag"
MIRROR_DIR="$DIR" python3 <<'PY'
import json, os, subprocess
meta = json.load(open("/tmp/mirror-meta"))
tag = meta["tag"]
root = os.environ["MIRROR_DIR"]
outdir = os.path.join(root, tag)
manifest = {"tag": tag, "assets": []}
for a in meta["assets"]:
    dest = os.path.join(outdir, a["name"])
    if not os.path.exists(dest):
        if subprocess.run(["curl", "-sfL", "-m", "300", "-o", dest + ".tmp",
                           a["dl"]]).returncode == 0:
            os.replace(dest + ".tmp", dest)
        else:
            continue  # asset failed — leave it out of the manifest
    manifest["assets"].append({"name": a["name"],
                               "url": "/releases/%s/%s" % (tag, a["name"])})
tmp = os.path.join(root, "latest.json.tmp")
with open(tmp, "w") as f:
    json.dump(manifest, f)
os.replace(tmp, os.path.join(root, "latest.json"))
PY
