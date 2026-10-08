#!/usr/bin/env python3
"""Offline, deterministic rendering of the firmware's 128x64 door screen."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
WIDTH, HEIGHT = 128, 64
MAX_MS = 0xFFFFFFFF


def number(value, name, maximum=MAX_MS / 1000):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= maximum:
        raise ValueError(f'{name} must be a finite number from 0 to {maximum}')
    return value


def integer(value, name, maximum=MAX_MS):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f'{name} must be an integer from 0 to {maximum}')
    return value


def load_timeline(path):
    events = []
    previous = 0
    ended = False
    fields = {
        'sync': {'status', 'age_s', 'relay_block', 'age_runs'},
        'door': {'state'},
        'keys': {'count', 'label'},
        'end': set(),
    }
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError('instruction must be a JSON object')
            if ended:
                raise ValueError('end must be the last instruction')
            at = number(event.get('at'), 'at')
            if at < previous:
                raise ValueError('timestamps must be in nondecreasing order')
            kind = event.get('set')
            if not isinstance(kind, str) or kind not in fields:
                raise ValueError('set must be sync, door, keys, or end')
            unknown = event.keys() - fields[kind] - {'at', 'set'}
            if unknown:
                raise ValueError(f'unknown fields: {", ".join(sorted(unknown))}')
            if kind == 'sync':
                if event.get('status') not in ('waiting', 'ok', 'stale'):
                    raise ValueError('sync status must be waiting, ok, or stale')
                if 'age_s' in event:
                    integer(event['age_s'], 'age_s')
                if 'relay_block' in event:
                    integer(event['relay_block'], 'relay_block')
                if 'age_runs' in event and type(event['age_runs']) is not bool:
                    raise ValueError('age_runs must be true or false')
            elif kind == 'door':
                if event.get('state') not in ('open', 'closed', 'denied'):
                    raise ValueError('door state must be open, closed, or denied')
            elif kind == 'keys':
                if ('count' in event) == ('label' in event):
                    raise ValueError('keys requires exactly one of count or label')
                if 'count' in event:
                    integer(event['count'], 'count', 11)
                else:
                    label = event['label']
                    if not isinstance(label, str) or any(not 32 <= ord(c) <= 126 for c in label):
                        raise ValueError('label must contain only printable ASCII')
                    if len(label) > 256:
                        raise ValueError('label must be at most 256 characters (display clips at 21)')
            else:
                if at <= 0:
                    raise ValueError('end must be after zero seconds')
                if events and events[-1]['at'] >= at:
                    raise ValueError('end must be later than the last state instruction')
                ended = True
            events.append(event)
            previous = at
        except (ValueError, TypeError) as exc:
            raise ValueError(f'{path}:{line_no}: {exc}') from exc
    if not ended:
        raise ValueError(f'{path}: missing final {{"at": seconds, "set": "end"}} instruction')
    return events


def build_renderer():
    compiler = shutil.which(os.environ.get('CXX', 'c++'))
    if not compiler:
        raise ValueError('C++ compiler missing: install g++ (Linux) or Xcode Command Line Tools (macOS)')
    sources = [HERE / 'main.cpp', HERE / 'vendor/adafruit-gfx/Adafruit_GFX.cpp']
    includes = [HERE / 'host', HERE / 'vendor/adafruit-gfx', ROOT / 'polkadot-lightclient/src']
    inputs = sorted((HERE / 'host').glob('*')) + sorted((HERE / 'vendor/adafruit-gfx').glob('*'))
    inputs += sources + [includes[-1] / 'door_screen.h', includes[-1] / 'door_animation.h']
    digest = hashlib.sha256(compiler.encode())
    for path in inputs:
        digest.update(path.read_bytes())
    cache = ROOT / '.render-cache'
    cache.mkdir(exist_ok=True)
    binary = cache / ('door-render-' + digest.hexdigest()[:20])
    if not binary.exists():
        # Build to a unique path so concurrent renders cannot run half-written binaries.
        with tempfile.TemporaryDirectory(dir=cache) as tmp:
            target = Path(tmp) / 'renderer'
            subprocess.run([compiler, '-std=c++17', '-O2', '-DARDUINO=100',
                            *['-I' + str(p) for p in includes], *map(str, sources), '-o', str(target)], check=True)
            target.replace(binary)
    return binary


def frame_states(events, fps):
    """Emit complete frame states; all events at/before a frame apply in file order."""
    state = dict(status='waiting', age_s=0, relay_block=0, age_runs=True,
                 age_at=0, unlocked=False, denied=False, denied_ms=0, closed_event=0,
                 label='auth keys: 0')
    index = 0
    for frame in range(math.ceil(events[-1]['at'] * fps)):
        time = frame / fps
        while index < len(events) - 1 and events[index]['at'] <= time + 1e-10:
            event = events[index]
            at = event['at']
            kind = event['set']
            if kind == 'sync':
                age = state['age_s'] + (at - state['age_at'] if state['age_runs'] else 0)
                state.update(status=event['status'], age_s=event.get('age_s', age), age_at=at,
                             relay_block=event.get('relay_block', state['relay_block']),
                             age_runs=event.get('age_runs', state['age_runs']))
            elif kind == 'door':
                if event['state'] == 'closed':
                    state['closed_event'] += 1
                state['unlocked'] = event['state'] == 'open'
                state['denied'] = event['state'] == 'denied'
                if state['denied']:
                    state['denied_ms'] = round(at * 1000)
            elif kind == 'keys':
                state['label'] = event.get('label', f'auth keys: {event.get("count", 0)}')
            index += 1
        age = min(MAX_MS, int(state['age_s'] + (time - state['age_at'] if state['age_runs'] else 0) + 1e-9))
        values = (round(time * 1000), int(state['unlocked']), int(state['status'] == 'ok'),
                  int(state['status'] != 'waiting'), age, state['relay_block'],
                  int(state['denied']), state['denied_ms'], state['closed_event'])
        yield (' '.join(map(str, values)) + ' ' + state['label'] + '\n').encode('ascii')


def render(events, output, fps=40, scale=1, overwrite=False, margin=16, glow=True):
    if not 0 <= margin <= 1024:
        raise ValueError('margin must be 0–1024 native pixels')
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        raise ValueError('FFmpeg missing: brew install ffmpeg (macOS) or sudo apt install ffmpeg (Linux)')
    if output.suffix.lower() not in ('.mp4', '.mkv'):
        raise ValueError('output must end in .mp4 or .mkv')
    if output.exists() and not overwrite:
        raise ValueError(f'{output} already exists; use --overwrite to replace it')
    binary = build_renderer()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Spool tiny state records, then stream pixels directly between native code
    # and FFmpeg. Memory does not grow with video duration; no pipe deadlocks.
    with tempfile.TemporaryFile() as states, tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        for state in frame_states(events, fps):
            states.write(state)
        states.seek(0)
        # Measure the occupied area over the whole clip, keeping the framing
        # fixed as labels change and the symbol animates.
        left, top, right, bottom = WIDTH, HEIGHT, -1, -1
        if margin:
            with subprocess.Popen([str(binary)], stdin=states, stdout=subprocess.PIPE) as probe:
                while True:
                    frame = probe.stdout.read(WIDTH * HEIGHT)
                    if not frame:
                        break
                    if len(frame) != WIDTH * HEIGHT:
                        raise ValueError('incomplete native frame')
                    for y in range(HEIGHT):
                        row = frame[y*WIDTH:(y+1)*WIDTH]
                        first = row.find(b'\xff')
                        if first >= 0:
                            left, right = min(left, first), max(right, row.rfind(b'\xff'))
                            top, bottom = min(top, y), max(bottom, y)
                probe.stdout.close()
                if probe.wait() != 0:
                    raise ValueError('native renderer failed')
            states.seek(0)
        if right < left:
            left, top, right, bottom = 0, 0, WIDTH-1, HEIGHT-1
        crop_w, crop_h = right-left+1, bottom-top+1
        canvas_w, canvas_h = WIDTH+2*margin, HEIGHT+2*margin
        offset_x, offset_y = (canvas_w-crop_w)//2, (canvas_h-crop_h)//2
        target = Path(tmp) / output.name
        encoder = ['-c:v', 'libx264', '-preset', 'medium', '-crf', '1', '-profile:v', 'high', '-pix_fmt', 'yuv420p', '-movflags', '+faststart']
        if output.suffix.lower() == '.mkv':
            encoder = ['-c:v', 'ffv1', '-pix_fmt', 'bgr0' if glow else 'gray']
        # Gray pad uses limited-range black (16). Native pixels are only 0/255,
        # so normalize the border to full-range black before scaling/encoding.
        filters = (
            f"format=gray,crop={crop_w}:{crop_h}:{left}:{top}:exact=1,"
            f"pad={canvas_w}:{canvas_h}:{offset_x}:{offset_y}:color=black,"
            f"lut=y='if(eq(val,16),0,val)',scale=iw*{scale}:ih*{scale}:flags=neighbor"
        )
        if glow:
            # Add light around the sharp pixel cores at two distances. Blur in
            # output pixels so the OLED appearance stays consistent at any scale.
            filters += (
                f",split=3[core][near][wide];"
                f"[near]gblur=sigma={0.7*scale}:steps=3[near_glow];"
                f"[wide]gblur=sigma={2.8*scale}:steps=3[wide_glow];"
                "[core][near_glow]blend=all_expr='min(255,A+0.8*B)'[lit];"
                "[lit][wide_glow]blend=all_expr='min(255,A+0.55*B)',"
                # Let bright cores approach pure white; retain blue in the halo.
                "format=rgb24,lutrgb=r='val*(0.88+0.10*val/255)':g='val*(0.95+0.04*val/255)':b=val"
            )
        with subprocess.Popen([str(binary)], stdin=states, stdout=subprocess.PIPE) as renderer:
            try:
                result = subprocess.run([ffmpeg, '-hide_banner', '-loglevel', 'error', '-y',
                                         '-f', 'rawvideo', '-pixel_format', 'gray', '-video_size', '128x64',
                                         '-framerate', str(fps), '-i', 'pipe:0', '-an',
                                         '-filter_complex', filters,
                                         *encoder, str(target)], stdin=renderer.stdout)
            finally:
                renderer.stdout.close()
            if renderer.wait() != 0:
                raise ValueError('native renderer failed')
            if result.returncode:
                raise ValueError('FFmpeg failed (see error above)')
        if overwrite:
            target.replace(output)
        else:
            # Atomic no-clobber publication, including two simultaneous renders.
            os.link(target, output)
    return math.ceil(events[-1]['at'] * fps)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('instructions', type=Path, help='JSONL timeline; see demos/door.jsonl')
    parser.add_argument('-o', '--output', type=Path, help='default: renders/<timeline>.mp4; .mkv uses lossless FFV1')
    parser.add_argument('--fps', type=int, default=40, help='frames per second, 1–120 (default: 40, matching 25 ms animation ticks)')
    parser.add_argument('--scale', type=int, default=1, help='integer nearest-neighbor scale, 1–32 (default: native 128x64)')
    parser.add_argument('--margin', type=int, default=16, help='black margin on every side in native pixels, scaled with the display (default: 16; 0 for raw screen)')
    parser.add_argument('--no-glow', action='store_true', help='disable the OLED halo and blue tint for exact black/white pixels')
    parser.add_argument('--overwrite', action='store_true')
    args = parser.parse_args()
    try:
        if not 1 <= args.fps <= 120 or not 1 <= args.scale <= 32:
            raise ValueError('fps must be 1–120 and scale must be 1–32')
        events = load_timeline(args.instructions)
        output = (args.output or ROOT / 'renders' / (args.instructions.stem + '.mp4')).resolve()
        frames = render(events, output, args.fps, args.scale, args.overwrite, args.margin, glow=not args.no_glow)
        print(f'{output}\n{(WIDTH+2*args.margin)*args.scale}×{(HEIGHT+2*args.margin)*args.scale}, {args.fps} fps, {frames} frames, {frames/args.fps:g} s')
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'render: {exc}\n')


if __name__ == '__main__':
    main()
