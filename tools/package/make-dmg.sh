#!/bin/bash
#
# Phase 10 packaging: .build/release/FreerForMac -> dist/Freer-<version>.dmg
#
# Builds release, wraps the SwiftPM executable in a real `Freer.app`, signs it
# under the hardened runtime, and rolls a compressed disk image with the usual
# drag-to-/Applications layout.
#
# Signing takes the best identity on hand, and the three outcomes differ only
# in how much work the recipient has to do:
#
#   Developer ID + NOTARY_PROFILE  Apple vouches for the build. Double-click,
#                                  drag, done — no warning at any point.
#   Developer ID alone             Signed, timestamped, hardened. Gatekeeper
#                                  still blocks a copy that arrives with a
#                                  quarantine flag, because it isn't notarised.
#   ad-hoc                         No Apple account involved and no certificate
#                                  that can ever be revoked. Every recipient
#                                  has to let it through by hand.
#
# The last two both ship 安装说明.txt inside the image explaining the click-path.
#
#   tools/package/make-dmg.sh                 # build, sign, package
#   SKIP_BUILD=1 tools/package/make-dmg.sh    # reuse .build/release
#   SIGN_ID=- tools/package/make-dmg.sh       # force ad-hoc even if a cert exists
#   NOTARY_PROFILE=freer tools/package/make-dmg.sh
#       ^ also submit to Apple and staple the ticket. Requires a live paid
#         membership — an expired one fails the submission, it does not fall
#         back. The profile is one you created once with:
#           xcrun notarytool store-credentials freer \
#             --apple-id <you@example.com> --team-id 5768V787GP \
#             --password <app-specific-password>
#
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT=$PWD
DIST=$ROOT/dist
APP=$DIST/Freer.app
PLIST=$ROOT/Sources/FreerForMac/Info.plist

VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$PLIST")
BUILD=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$PLIST")
DMG=$DIST/Freer-$VERSION.dmg

# ---------------------------------------------------------------- identity
# An absent Developer ID is a normal state, not an error: without a paid
# membership there is no certificate to be had, and ad-hoc still produces a
# working app. `SIGN_ID=-` forces that path even when a certificate exists.
SIGN_ID=${SIGN_ID:-$(security find-identity -v -p codesigning \
    | awk -F'"' '/Developer ID Application/ {print $2; exit}')}
if [ -z "$SIGN_ID" ]; then
    SIGN_ID=-
fi

ADHOC=
[ "$SIGN_ID" = "-" ] && ADHOC=1

if [ -n "$ADHOC" ] && [ -n "${NOTARY_PROFILE:-}" ]; then
    echo "NOTARY_PROFILE is set, but an ad-hoc signature carries no team for" >&2
    echo "Apple to notarise against — ignoring it." >&2
    NOTARY_PROFILE=
fi

echo "==> Freer $VERSION ($BUILD)"
if [ -n "$ADHOC" ]; then
    echo "    identity: ad-hoc — runs anywhere, vouched for by nobody"
else
    echo "    identity: $SIGN_ID"
fi

# ---------------------------------------------------------------- build
if [ -z "${SKIP_BUILD:-}" ]; then
    echo "==> swift build -c release"
    swift build -c release
fi
BIN=$ROOT/.build/release/FreerForMac
[ -x "$BIN" ] || { echo "missing $BIN" >&2; exit 1; }

# ---------------------------------------------------------------- bundle
echo "==> assembling Freer.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BIN" "$APP/Contents/MacOS/FreerForMac"
cp "$PLIST" "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"

swift "$ROOT/tools/package/make-icon.swift" "$APP/Contents/Resources/Freer.icns"
/usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string Freer" "$APP/Contents/Info.plist"

# SwiftPM's generated `Bundle.module` accessor wants the resource bundle at
# `Bundle.main.bundleURL/<name>.bundle` — the .app root, where codesign refuses
# to seal anything. They go in Contents/Resources instead, and FCUI's
# `Bundle.fcuiResources` looks there first (see ResourceBundle.swift).
for b in "$ROOT"/.build/release/*.bundle; do
    [ -e "$b" ] || continue
    cp -R "$b" "$APP/Contents/Resources/$(basename "$b")"
done

# Some dependencies ship read-only resources (GRDB's PrivacyInfo.xcprivacy is
# 0444 in its own checkout) and SwiftPM copies the mode along with the file.
# `xattr -dr com.apple.quarantine` then fails loudly on exactly those files —
# harmless, since clearing the bundle root is what lifts the block, but it
# looks like a failed install to whoever is following 安装说明.txt.
chmod -R u+w "$APP/Contents/Resources"

# ---------------------------------------------------------------- sign
# Mic and camera are TCC-gated, and under the hardened runtime the entitlement
# has to be there as well as the usage string in Info.plist. This holds for the
# ad-hoc build too — the runtime is what makes the entitlement necessary, and
# keeping both paths identical means testing one tests the other.
ENTITLEMENTS=$DIST/Freer.entitlements
cat > "$ENTITLEMENTS" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.device.audio-input</key>
	<true/>
	<key>com.apple.security.device.camera</key>
	<true/>
	<key>com.apple.security.network.client</key>
	<true/>
	<key>com.apple.security.network.server</key>
	<true/>
</dict>
</plist>
PLIST

echo "==> signing"
# An ad-hoc signature has no certificate for Apple's timestamp authority to
# bind to. `--timestamp` there is silently ignored rather than refused, so ask
# for none outright and keep the build log honest about what was produced.
TIMESTAMP=--timestamp
[ -n "$ADHOC" ] && TIMESTAMP=--timestamp=none

# The `.bundle` directories hold no code — SwiftPM's `.copy` leaves them flat,
# without even the Contents/ a macOS bundle would need — so they are not signed
# separately. The app's own seal covers them as resources.
codesign --force --sign "$SIGN_ID" "$TIMESTAMP" --options runtime \
    --entitlements "$ENTITLEMENTS" "$APP"

codesign --verify --deep --strict --verbose=2 "$APP"

# ---------------------------------------------------------------- notarise
if [ -n "${NOTARY_PROFILE:-}" ]; then
    echo "==> notarising the app"
    ZIP=$DIST/Freer-notarize.zip
    rm -f "$ZIP"
    ditto -c -k --keepParent "$APP" "$ZIP"
    xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$APP"
    rm -f "$ZIP"
fi

# ---------------------------------------------------------------- dmg
echo "==> building $(basename "$DMG")"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp -R "$APP" "$STAGE/Freer.app"
ln -s /Applications "$STAGE/Applications"

# Anything short of a stapled ticket means the recipient meets a scary dialog,
# so the way past it travels in the image rather than in a chat message.
if [ -z "${NOTARY_PROFILE:-}" ]; then
    cat > "$STAGE/安装说明.txt" <<'TXT'
Freer 安装说明
==============

本应用没有经过 Apple 公证（notarization），所以从网上下载后第一次打开
时，macOS 会拦下它。这不是因为它有问题。下面两种方式任选。


最省事：U 盘 / 局域网 / 直接拷贝
--------------------------------
如果这个 DMG 是通过 U 盘、局域网共享或本机直接拷贝拿到的，macOS 不会
给它打"隔离"标记，拖进"应用程序"后双击即可打开，全程没有任何拦截。
分发时优先用这种方式。


从网页、邮件、聊天软件下载的
----------------------------

1. 把左边的 Freer 拖到右边的"应用程序"文件夹。

2. 双击打开。系统会提示"无法打开，因为无法验证开发者"。
   点"完成"或"取消"关掉这个提示。

3. 打开"系统设置" → "隐私与安全性"，向下滚动，会看到一行
   "已阻止使用 Freer"，点右边的"仍要打开"，再确认一次。

4. 只需放行一次，以后打开不再提示。


⚠️ 不要使用 xattr 命令
----------------------
网上常见的这条命令，在 macOS 15 及以后（含 macOS 26）已经没用了：

    xattr -dr com.apple.quarantine /Applications/Freer.app

清掉隔离标记并不会撤销系统已经记下的拦截记录，反而会让"隐私与安全性"
里的"仍要打开"按钮不再出现——等于把自己锁在门外。请走上面第 3 步。

同样，`sudo spctl --add` 也已经被 Apple 移除，不要再用。


图标一直在 Dock 上跳、窗口不出现？
----------------------------------
这就是被系统拦住的样子：进程在启动最开始就被冻结，不会报错，也不会
自己退出。按下面顺序处理：

  1. 先按上面第 3 步，在"隐私与安全性"里点"仍要打开"。

  2. 如果那里已经看不到 Freer 这一行：把"应用程序"里的 Freer 删掉，
     从 DMG 重新拖一次，再做第 3 步。

  3. 系统的拦截记录是和"Freer.app"这个名字绑定的。万一上面都无效，
     把应用改个名字（例如改成 Freer2.app）再打开，即可正常启动。

处理前建议先强制退出已经卡住的进程：在"活动监视器"里找到 FreerForMac
结束它，或在"终端"里执行 pkill -9 FreerForMac。


系统要求
--------
  macOS 14.0 或更高版本
  Apple 芯片（M1/M2/M3/M4）；不支持 Intel 机型
TXT
fi

rm -f "$DMG"
hdiutil create -volname "Freer $VERSION" -srcfolder "$STAGE" \
    -fs HFS+ -format UDZO -imagekey zlib-level=9 -ov -quiet "$DMG"

# Signing the image is only worth doing with a real identity behind it; an
# ad-hoc seal on a .dmg names nobody and proves nothing.
if [ -z "$ADHOC" ]; then
    codesign --force --sign "$SIGN_ID" --timestamp "$DMG"
fi

if [ -n "${NOTARY_PROFILE:-}" ]; then
    echo "==> notarising the disk image"
    xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$DMG"
fi

echo
echo "==> $DMG"
ls -lh "$DMG" | awk '{print "    " $5}'
spctl --assess --type execute --verbose=2 "$APP" 2>&1 | sed 's/^/    /' || true
if [ -z "${NOTARY_PROFILE:-}" ]; then
    echo "    (expected — the image ships 安装说明.txt telling recipients how to proceed)"
fi
