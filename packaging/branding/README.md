# Spark branding assets

Source-of-truth vector art for the app icon and the macOS DMG installer, plus how to regenerate the
derived assets.

## Icon — "Spark Bolt"

`spark-icon.svg` — a lightning **bolt** (amber gradient `#ffd54a → #f2a900`) on a cyan squircle
(`#18d4ea → #009cb4`) with a modern macOS treatment (rounded-rect container, top sheen, soft depth
shadow on the bolt). It literally reads "Spark," stays crisp down to 16 px, and uses the brand palette
already in the app UI (cyan `#00bdd6` + amber "bolt" `#f5b800`).

Regenerate the full cross-platform icon set (macOS `.icns`, Windows `.ico` + tiles, iOS AppIcon,
Android mipmaps) from the master:

```bash
rsvg-convert -w 1024 -h 1024 packaging/branding/spark-icon.svg -o /tmp/spark-1024.png   # brew install librsvg
cd gui-tauri && npx @tauri-apps/cli icon /tmp/spark-1024.png
```

`spark-icon-1024.png` is the last-rendered 1024 master (checked in for convenience).

### Android adaptive icon

`tauri icon` emits the *full squircle* as the adaptive **foreground** layer, which double-masks
(squircle-inside-launcher-mask) and shrinks the glyph. Instead we split it the way Android
adaptive icons want: the cyan is the **background** layer and only the bolt is the
**foreground**, sized to stay inside the 66/108 safe zone under any launcher mask.

- `spark-icon-android-foreground.svg` — bolt only, transparent background, scaled ~0.8 and
  centered. Rendered over the five `mipmap-*/ic_launcher_foreground.png` densities
  (108/162/216/324/432 px for mdpi→xxxhdpi).
- `values/ic_launcher_background.xml` — `ic_launcher_background` set to brand cyan `#0CB8CF`
  (the squircle gradient's midpoint), replacing tauri's default `#fff`.
- The legacy pre-masked bitmaps (`ic_launcher.png`, `ic_launcher_round.png`, used on
  launchers without adaptive support) keep the full squircle art from `tauri icon`.

Regenerate the foreground layer after editing the SVG:

```bash
res=gui-tauri/src-tauri/gen/android/app/src/main/res
for d in mdpi:108 hdpi:162 xhdpi:216 xxhdpi:324 xxxhdpi:432; do
  dir=${d%:*}; px=${d#*:}
  rsvg-convert -w "$px" -h "$px" packaging/branding/spark-icon-android-foreground.svg \
    -o "$res/mipmap-$dir/ic_launcher_foreground.png"
done
```

## DMG installer

`dmg-background.svg` → `dmg-background.png` (rendered at 1440×960, tagged 144 dpi so it displays crisp
at the 720×480-pt window). A light gradient with the "⚡ Spark" wordmark, a cyan drag arrow, a faint
bolt watermark, and a "Drag Spark into your Applications folder" caption.

`packaging/macos/build-tauri-dmg.sh` lays the DMG window out (icon view, hidden toolbar/sidebar, the
background above, 128-px icons: `Spark.app` at {200,235}, `Applications` at {520,235}) via a Finder
`osascript` pass on a read-write image, then compresses to UDZO. The volume also carries a custom
icon (`.VolumeIcon.icns` = the app icon). If Finder automation is unavailable (headless CI without an
Aqua session / no Automation TCC grant), the script logs a warning and falls back to the default
layout so the build still succeeds.

Regenerate the background:

```bash
rsvg-convert -w 1440 -h 960 packaging/branding/dmg-background.svg -o packaging/branding/dmg-background.png
sips -s dpiWidth 144 -s dpiHeight 144 packaging/branding/dmg-background.png
```
