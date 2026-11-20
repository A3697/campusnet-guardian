"""Prepare versioned downloads and a checksum manifest; never publish to GitHub by itself."""
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from campusnet import __version__
from campusnet.updater import UpdateInfo, version_key


def main():
    version = version_key(__version__)
    build = "{}.{}".format(version[3], version[4])
    source = ROOT / "packaging/output" / ("校园网连接守护-" + build + "-安装包.exe")
    data = source.read_bytes()
    info = UpdateInfo(__version__, "CampusNetGuardian-" + build + "-Setup.exe",
                      hashlib.sha256(data).hexdigest(), len(data),
                      (ROOT / "release/UPDATE_NOTES.txt").read_text(encoding="utf-8").strip())
    destination = ROOT / "downloads"
    destination.mkdir(exist_ok=True)
    shutil.copy2(source, destination / info.filename)
    (destination / "SHA256.txt").write_text(info.sha256 + "  " + info.filename + "\n", encoding="utf-8", newline="\n")
    (destination / "latest.json").write_text(json.dumps(dict(schema=1, **info.__dict__), ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("已生成版本安装包、SHA-256 校验值和 GitHub 更新信息。")


if __name__ == "__main__":
    main()
