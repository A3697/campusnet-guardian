"""Bundle current application sources and the LGPL tray component for the installer."""
from importlib.util import find_spec
from pathlib import Path
import shutil
from zipfile import ZIP_DEFLATED, ZipFile


def main():
    root = Path(__file__).resolve().parents[1]
    payload = root / "packaging" / "payload"
    for name in ("使用说明.txt", "AUTHORS.md", "LICENSE"):
        shutil.copy2(root / name, payload / name)
    tray = find_spec("pystray")
    if tray is None or not tray.origin:
        raise RuntimeError("请先安装 requirements-build.txt 中的构建依赖。")
    files = [root / name for name in (
        "campusnet_gui.py", "CampusNetGuardian.spec", "requirements-build.txt",
        "pyproject.toml", "README.md", "RELEASE_NOTES.md", "AUTHORS.md", "LICENSE", "使用说明.txt",
        "release/app_icon.ico", "packaging/app_icon.ico", "packaging/CampusNetGuardian.iss",
        "packaging/build-installer.ps1", "packaging/prepare-source.py", "packaging/publish-files.py",
        "release/UPDATE_NOTES.txt", "packaging/payload/default-config.json",
    )]
    for folder in ("campusnet", "tests"):
        files.extend(sorted((root / folder).rglob("*.py")))
    files.extend(sorted((payload / "licenses").rglob("*")))
    files.extend(sorted((root / "third_party/7zip").rglob("*")))
    with ZipFile(payload / "源码与构建.zip", "w", ZIP_DEFLATED) as archive:
        for path in files:
            if path.is_file():
                archive.write(path, "app/" + path.relative_to(root).as_posix())
        tray_root = Path(tray.origin).parent
        for path in sorted(tray_root.rglob("*.py")):
            archive.write(path, "third_party/pystray/" + path.relative_to(tray_root).as_posix())
        for license_dir in sorted((payload / "licenses").glob("pystray*")):
            for path in sorted(license_dir.rglob("*")):
                if path.is_file():
                    archive.write(path, "third_party/" + path.relative_to(payload / "licenses").as_posix())
        archive.writestr("构建说明.txt", "应用源码位于 app，构建步骤见 app/README.md。\n"
                        "托盘组件源码位于 third_party/pystray，可替换构建环境中同名组件后重新打包。\n"
                        "本源码包不包含个人账号、密码、配置和运行日志。\n")
    print("已更新安装包内的应用源码、托盘组件源码和使用说明。")


if __name__ == "__main__":
    main()
