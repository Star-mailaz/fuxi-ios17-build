import plistlib
import sys

bm = plistlib.load(open(sys.argv[1], "rb"))
roles = {}
allkeys = set()
for bi in bm.get("BuildIdentities", []):
    man = bi.get("Manifest") or {}
    allkeys.update(man.keys())
    for key in ("OS", "SystemOS", "AppOS"):
        node = man.get(key) or {}
        info = node.get("Info") or {}
        path = info.get("Path")
        if path and key not in roles:
            roles[key] = path
for key, value in roles.items():
    print(f"{key}={value}")
sys.stderr.write("# manifest keys: " + " ".join(sorted(allkeys)) + "\n")
