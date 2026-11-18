import plistlib
import sys

KEYS = {
    "OS": "OS",
    "Cryptex1,SystemOS": "SystemOS",
    "Cryptex1,AppOS": "AppOS",
    "SystemVolume": "SystemVolume",
    "Cryptex1,SystemVolume": "SystemVolume2",
    "Cryptex1,AppVolume": "AppVolume",
}

bm = plistlib.load(open(sys.argv[1], "rb"))
roles = {}
allkeys = set()
for bi in bm.get("BuildIdentities", []):
    man = bi.get("Manifest") or {}
    allkeys.update(man.keys())
    for key, want in KEYS.items():
        node = man.get(key) or {}
        info = node.get("Info") or {}
        path = info.get("Path")
        if path and want not in roles:
            roles[want] = path
for key, value in roles.items():
    print(f"{key}={value}")
sys.stderr.write("# manifest keys: " + " ".join(sorted(allkeys)) + "\n")
