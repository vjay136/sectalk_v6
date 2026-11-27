#!/usr/bin/env bash
set -euo pipefail

apk=$1
output=$2
mode=${3:-debug}
package=com.eaglesecurity.sectalk
chrome=com.android.chrome
hierarchy=/sdcard/sectalk-render.xml
host=sectalk-v6-pilot.vercel.app

if [[ $mode != debug && $mode != signed ]]; then
  printf 'Unknown Android render mode: %s\n' "$mode" >&2
  exit 2
fi

mkdir -p "$output"
capture() {
  local result=$?
  trap - EXIT
  if timeout 15s adb exec-out screencap -p > "$output/sectalk-android.png"; then
    if ! test -s "$output/sectalk-android.png"; then
      rm "$output/sectalk-android.png"
      result=1
    fi
  else
    rm -f "$output/sectalk-android.png"
    result=1
  fi
  if (( result != 0 )); then
    timeout 15s adb shell dumpsys activity activities > "$output/activities.txt" || true
    timeout 15s adb logcat -d -b crash -v threadtime > "$output/android-crash.txt" || true
    timeout 15s adb logcat -d -b main -b system -v threadtime \
      AndroidRuntime:E ActivityTaskManager:I ActivityManager:I LauncherActivity:D TwaLauncher:D \
      chromium:W '*:S' > "$output/android-launch-log.txt" || true
  fi
  exit "$result"
}
trap capture EXIT

sha256sum "$apk" | tee "$output/apk.sha256"
"$ANDROID_HOME/build-tools/35.0.0/aapt2" dump xmltree "$apk" --file AndroidManifest.xml > "$output/apk-manifest.txt"
for declaration in android.permission.POST_NOTIFICATIONS \
  com.google.androidbrowserhelper.trusted.NotificationPermissionRequestActivity \
  com.google.androidbrowserhelper.trusted.DelegationService \
  android.support.customtabs.trusted.TRUSTED_WEB_ACTIVITY_SERVICE; do
  grep -Fq "$declaration" "$output/apk-manifest.txt"
done
adb shell pm path "$chrome"
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard
# The clean emulator can start Chrome's custom tab without the first-run screen.
adb shell am set-debug-app --persistent "$chrome"
adb shell 'echo "chrome --disable-fre" > /data/local/tmp/chrome-command-line'
adb shell am force-stop "$chrome"
adb install -r "$apk"
adb logcat -b main -b system -b crash -c

if [[ $mode == signed ]]; then
  adb shell pm verify-app-links --re-verify "$package"
  for (( attempt=1; attempt<=30; attempt++ )); do
    adb shell pm get-app-links "$package" > "$output/app-links.txt"
    if awk -v host="$host:" '$1 == host && $2 == "verified" { verified = 1 } END { exit !verified }' "$output/app-links.txt"; then
      break
    fi
    sleep 3
  done
  if (( attempt > 30 )); then
    printf 'Android App Links did not verify %s.\n' "$host" | tee "$output/result.txt" >&2
    exit 1
  fi
fi

adb shell am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \
  -n "$package/.SecTalkActivity" | tee "$output/launch.txt"
debug_port=$(adb forward tcp:0 localabstract:chrome_devtools_remote)

for (( attempt=1; attempt<=12; attempt++ )); do
  adb shell rm -f "$hierarchy"
  if timeout 12s adb shell uiautomator dump "$hierarchy" &&
    adb pull "$hierarchy" "$output/window.xml"; then
    curl -fsS --max-time 2 "http://127.0.0.1:$debug_port/json/list" > "$output/chrome-targets.json" || true
    if python3 - "$output" "$host" "$mode" <<'PY'
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

output, host, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
nodes = list(ET.parse(output / 'window.xml').iter('node'))
content = ' '.join(node.get('text', '') + ' ' + node.get('content-desc', '') for node in nodes)
if 'Private by design.' not in content or 'Yours to control.' not in content:
    sys.exit(1)
if mode == 'signed':
    sys.exit(0)

try:
    targets = json.loads((output / 'chrome-targets.json').read_text())
except json.JSONDecodeError:
    targets = []
if any(target.get('type') == 'page' and urlparse(target.get('url', '')).hostname == host
       and urlparse(target.get('url', '')).scheme == 'https' for target in targets):
    sys.exit(0)

for node in nodes:
    if node.get('resource-id', '') != 'com.android.chrome:id/url_bar':
        continue
    address = node.get('text', '') or node.get('content-desc', '')
    if address.removeprefix('https://').rstrip('/') == host:
        sys.exit(0)
sys.exit(1)
PY
    then
      printf 'The Android launcher rendered SecTalk from https://%s/.\n' "$host" | tee "$output/result.txt"
      exit 0
    fi
  fi
  sleep 2
done

echo 'Expected SecTalk URL and page text were not visible on Android.' | tee "$output/result.txt" >&2
exit 1
