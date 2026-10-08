import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import render


class RendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = render.build_renderer()

    def timeline(self, lines):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'timeline.jsonl'
            path.write_text('\n'.join(json.dumps(line) for line in lines))
            return render.load_timeline(path)

    def pixels(self, events, fps=40):
        return subprocess.run([self.binary], input=b''.join(render.frame_states(events, fps)),
                              stdout=subprocess.PIPE, check=True).stdout

    def test_validation_reports_line_and_rejects_bad_timelines(self):
        cases = [
            [{'at': 0, 'set': 'door', 'state': 'opne'}],
            [{'at': 0, 'set': 'keys', 'count': 12}],
            [{'at': 0, 'set': 'keys', 'label': 'bad\nlabel'}],
            [{'at': 0, 'set': 'sync', 'status': 'ok', 'relay_block': -1}],
            [{'at': 0, 'set': 'sync', 'status': 'ok', 'age_runs': 1}],
            [{'at': 0, 'set': 'sync', 'status': 'ok', 'delay': 1}],
            [{'at': float('nan'), 'set': 'door', 'state': 'open'}],
            [{'at': 2, 'set': 'door', 'state': 'open'}, {'at': 1, 'set': 'end'}],
            [{'at': 1, 'set': 'end'}, {'at': 2, 'set': 'end'}],
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaisesRegex(ValueError, r'timeline.jsonl:\d+:'):
                self.timeline(case)
        with self.assertRaisesRegex(ValueError, 'missing final'):
            self.timeline([{'at': 0, 'set': 'door', 'state': 'open'}])

    def test_age_freezing_and_simultaneous_events(self):
        events = self.timeline([
            {'at': 0, 'set': 'sync', 'status': 'ok', 'age_s': 29, 'relay_block': 989094},
            {'at': 1, 'set': 'sync', 'status': 'stale', 'age_runs': False},
            {'at': 1, 'set': 'keys', 'count': 2},
            {'at': 1, 'set': 'door', 'state': 'open'},
            {'at': 3, 'set': 'end'},
        ])
        states = [line.decode().split(' ', 9) for line in render.frame_states(events, 2)]
        self.assertEqual(states[0][4:6], ['29', '989094'])
        self.assertEqual(states[2][1:6], ['1', '0', '1', '30', '989094'])
        self.assertEqual(states[-1][4], '30')
        self.assertEqual(states[2][9], 'auth keys: 2\n')

    def test_repeated_closed_events_replay_closing_animation(self):
        events = self.timeline([
            {'at': 0, 'set': 'door', 'state': 'closed'},
            {'at': 1, 'set': 'door', 'state': 'closed'},
            {'at': 1.3, 'set': 'door', 'state': 'closed'},
            {'at': 2, 'set': 'end'},
        ])
        pixels = self.pixels(events)
        def frame(index):
            return pixels[index*8192:(index+1)*8192]
        # Initial close, close while settled, and close during closing all replay.
        self.assertEqual(frame(0), frame(40))
        self.assertEqual(frame(0), frame(52))
        self.assertNotEqual(frame(0), frame(12))
        self.assertNotEqual(frame(12), frame(24))
        self.assertEqual(frame(24), frame(39))
        self.assertEqual(frame(24), frame(76))
        idle = self.pixels(self.timeline([{'at': 0.025, 'set': 'end'}]))
        self.assertEqual(frame(24), idle)

    def test_open_flash_denial_and_resolution(self):
        events = self.timeline([
            {'at': 0, 'set': 'door', 'state': 'open'},
            {'at': 1, 'set': 'door', 'state': 'closed'},
            {'at': 2, 'set': 'door', 'state': 'denied'},
            {'at': 3, 'set': 'end'},
        ])
        pixels = self.pixels(events)
        self.assertEqual(len(pixels), 120 * 128 * 64)
        self.assertEqual(set(pixels), {0, 255})
        def region(frame, x0, y0, w, h):
            start = frame * 8192
            return b''.join(pixels[start+y*128+x0:start+y*128+x0+w] for y in range(y0, y0+h))
        def label(frame):
            return region(frame, 0, 21, 80, 16)
        self.assertIn(255, label(0))
        self.assertNotIn(255, label(12))  # 300 ms flash
        self.assertEqual(label(0), label(24))  # 600 ms, OPEN visible again
        self.assertNotEqual(label(0), label(40))  # CLOSED immediately
        self.assertNotIn(255, label(80))  # denial flash
        self.assertEqual(label(40), label(92))  # 300 ms later
        self.assertNotEqual(region(0, 80, 10, 48, 37), region(12, 80, 10, 48, 37))
        self.assertEqual(region(0, 80, 10, 48, 37), region(79, 80, 10, 48, 37))
        self.assertNotEqual(region(79, 80, 10, 48, 37), region(82, 80, 10, 48, 37))

    @unittest.skipUnless(shutil.which('ffmpeg') and shutil.which('ffprobe'), 'FFmpeg required')
    def test_oled_glow_has_cool_white_cores_and_soft_halo(self):
        events = self.timeline([{'at': 0.025, 'set': 'end'}])
        with tempfile.TemporaryDirectory() as tmp:
            for extension, scale in [('mp4', 1), ('mkv', 4)]:
                with self.subTest(extension=extension, scale=scale):
                    path = Path(tmp) / ('glow.' + extension)
                    render.render(events, path, scale=scale)
                    decoded = subprocess.check_output([
                        'ffmpeg', '-v', 'error', '-i', str(path),
                        '-f', 'rawvideo', '-pix_fmt', 'rgb24', 'pipe:1'])
                    pixels = list(zip(decoded[0::3], decoded[1::3], decoded[2::3]))
                    self.assertEqual(len(pixels), 160*96*scale*scale)
                    self.assertIn((0, 0, 0), pixels)
                    self.assertTrue(any(245 <= r < g < b and b >= 250 for r, g, b in pixels))
                    self.assertTrue(any(5 < b < 100 and r <= g <= b for r, g, b in pixels))

    @unittest.skipUnless(shutil.which('ffmpeg') and shutil.which('ffprobe'), 'FFmpeg required')
    def test_video_duration_dimensions_and_lossless_pixels(self):
        events = self.timeline([
            {'at': 0, 'set': 'sync', 'status': 'ok', 'age_s': 32, 'relay_block': 989094},
            {'at': 0, 'set': 'keys', 'count': 1},
            {'at': 0.1, 'set': 'door', 'state': 'open'},
            {'at': 0.8, 'set': 'end'},
        ])
        raw = self.pixels(events)
        # Independently measure all lit pixels and translate them as one group.
        lit = [(i % 8192 % 128, i % 8192 // 128) for i, value in enumerate(raw) if value]
        x0, x1 = min(x for x, y in lit), max(x for x, y in lit)
        y0, y1 = min(y for x, y in lit), max(y for x, y in lit)
        dx, dy = (160-(x1-x0+1))//2-x0, (96-(y1-y0+1))//2-y0
        self.assertGreater(dy, 16)  # Correct the unused bottom of the OLED.
        padded = bytearray(160*96*32)
        for i, value in enumerate(raw):
            if value:
                frame, pos = divmod(i, 8192)
                y, x = divmod(pos, 128)
                padded[frame*160*96+(y+dy)*160+x+dx] = value
        raw = bytes(padded)
        with tempfile.TemporaryDirectory(prefix='door render ') as tmp:
            for extension, scale in [('mp4', 1), ('mkv', 2)]:
                path = Path(tmp) / ('test video.' + extension)
                self.assertEqual(render.render(events, path, scale=scale, glow=False), 32)
                info = json.loads(subprocess.check_output([
                    'ffprobe', '-v', 'error', '-select_streams', 'v:0', '-count_frames',
                    '-show_entries', 'stream=width,height,nb_read_frames,r_frame_rate', '-of', 'json', str(path)]))['streams'][0]
                self.assertEqual((info['width'], info['height']), (160*scale, 96*scale))
                self.assertEqual(info['nb_read_frames'], '32')
                self.assertEqual(info['r_frame_rate'], '40/1')
                decoded = subprocess.check_output([
                    'ffmpeg', '-v', 'error', '-i', str(path), '-vf', 'scale=160:96:flags=neighbor',
                    '-f', 'rawvideo', '-pix_fmt', 'gray', 'pipe:1'])
                if extension == 'mkv':
                    self.assertEqual(decoded, raw)
                else:
                    # Compatible H.264 is near-lossless; FFV1 is the exact master.
                    self.assertEqual(len(decoded), len(raw))
                    errors = [abs(a-b) for a, b in zip(decoded, raw)]
                    self.assertLessEqual(max(errors), 16)
                    self.assertLess(sum(e*e for e in errors) / len(errors), 1)
                with self.assertRaisesRegex(ValueError, 'already exists'):
                    render.render(events, path)


if __name__ == '__main__':
    unittest.main()
