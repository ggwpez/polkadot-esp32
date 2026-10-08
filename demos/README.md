# Render a virtual door display

From the repository root:

```sh
just render demos/door.jsonl
# → renders/door.mp4, 160×96 pixels, 40 fps, 16 seconds

just render demos/door.jsonl --scale 8 -o renders/door-large.mp4
# → 1280×768, with sharp 8×8 pixel squares and a bright OLED glow

just render demos/door.jsonl --no-glow -o renders/door-master.mkv
# → lossless FFV1 master, exact black/white pixels
```

Requires Python 3.9+, a C++17 compiler (`c++`, or set `CXX`), FFmpeg with
libx264/FFV1, and `just`. No Python packages or hardware connection are needed.
On macOS, install Xcode Command Line Tools and `brew install just ffmpeg`;
on Debian/Ubuntu, install `g++ python3 ffmpeg` and `just`.
The native renderer compiles automatically and is cached in `.render-cache/`.
The visible content is centered within a 160×96 canvas by measuring its
occupied bounds across the entire clip. One fixed offset prevents movement
when labels change or the icon animates. The default adds 16 native pixels
on every side of the original canvas; unused OLED space is redistributed.
The margin scales with `--scale`; use `--margin 32` for more space, or
`--margin 0` for the original unpadded screen.
Lit pixels have a pronounced, broad halo by default, with sharp cool-white cores and a
slight blue tint against the black background. The glow scales with the display.
Use `--no-glow` to export the original crisp black/white pixels.
Use `--overwrite` to replace an existing output. `--fps 60` changes the frame
rate; `--help` lists options. Paths containing spaces are supported when quoted.
MP4 uses near-lossless H.264 High / YUV420 for playback and editing. MKV uses
lossless FFV1; combine it with `--no-glow` for exact framebuffer pixels.

## Timeline format

UTF-8 JSONL: one JSON object per line. Blank lines are allowed. Every command
has `at` (seconds from the start, including fractions) and `set`. Timestamps
must be nondecreasing; commands at the same timestamp apply in file order.
Finish with a `set: "end"` command later than the last state change.

```jsonl
{"at":0,"set":"sync","status":"ok","age_s":32,"relay_block":989094}
{"at":0,"set":"keys","count":1}
{"at":1,"set":"door","state":"open"}
{"at":3,"set":"door","state":"closed"}
{"at":4,"set":"sync","status":"stale","age_s":121,"relay_block":989094}
{"at":4,"set":"keys","count":0}
{"at":6,"set":"end"}
```

| `set` | Fields | Effect |
| --- | --- | --- |
| `sync` | Required `status`: `waiting`, `ok`, or `stale`. Optional `age_s`, `relay_block`, `age_runs`. | Sets the top line: `SYNC waiting`, `OK 32s R989094`, or `STALE 121s R989094`. |
| `door` | Required `state`: `open`, `closed`, or `denied`. | Opens/closes with the firmware's 600 ms triangle animation. Opening flashes the text once; denial closes and shakes the symbol for 720 ms, hiding CLOSED for the first 300 ms. |
| `keys` | Either `count`: 0–11, or `label`: printable ASCII. | Sets `auth keys: N`, or a custom bottom line. Long labels clip to 21 cells with `~`, as on the device. |
| `end` | No extra fields. | Ends the video at `at`. |

Initially the display is closed, waiting for sync, with zero authorized keys.
State persists until changed. Sync commands preserve omitted fields. Proof age
counts up each second; `"age_runs": false` freezes it for a deliberate shot.
For example, `{"at":0,"set":"sync","status":"ok","age_s":35,"relay_block":989094,"age_runs":false}`
holds `OK 35s R989094` until another sync command. Set `age_runs` back to true
to resume aging. The firmware omits the relay block if the full top line would
exceed 21 columns.

These are explicit display-state commands: an age passing 120 seconds does
not automatically set STALE, close the door, or clear the keys. Set those
states together at the desired timestamp, as in the example. Repeating
`closed` while already closed restarts the full 600 ms closing animation,
including at timestamp zero or while a previous closing animation is running.
Repeating `open` while already open leaves the animation alone; repeating `denied`
restarts the denial effect. Interrupted opening/closing continues from the
current animation position.

Commands apply on the first video frame at or after their timestamp. Align
changes to 0.025-second intervals at the default 40 fps for exact placement.
Video length is rounded up to a whole frame. Use an explicit final `end` to
hold the last state long enough to be seen.

## Fidelity and checks

The firmware and renderer share `src/door_screen.h` and `src/door_animation.h`.
The host uses the same Adafruit GFX 1.12.6 drawing primitives and classic
bitmap font as the firmware; the dependency is vendored with its license.
The OPEN/CLOSED baseline remains at y=21, including the recent 2-pixel move.
All frames are first rasterized at the OLED's native **128×64** resolution;
scaling duplicates pixels before the optional glow is added. The render clock is deterministic and offline,
with no network, wallet, proof verification, or physical OLED refresh jitter.
Other frame rates sample the shared animation at their respective intervals.

```sh
just test-render
pio run -d polkadot-lightclient -e esp32dev
```

Tests check malformed instructions, simultaneous changes, running/frozen proof
age, opening/denial flashes, moving symbols, frame counts, resolution, MP4
pixel error, exact FFV1 decoding, and refusal to overwrite an existing video.
