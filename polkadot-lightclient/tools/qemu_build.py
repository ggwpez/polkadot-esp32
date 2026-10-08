"""PlatformIO hook: embed the existing devnet fixtures and compile test adapters."""
from pathlib import Path

Import("env")
project = Path(env.subst("$PROJECT_DIR"))
generated = Path(env.subst("$BUILD_DIR")) / "generated"
generated.mkdir(parents=True, exist_ok=True)
lines = []
files = sorted((project / "test/fixtures/devnet").glob("*.bin"))
for i, path in enumerate(files):
    data = path.read_bytes()
    lines.append(f"static const uint8_t fixture_{i}[] = {{")
    for offset in range(0, len(data), 16):
        lines.append(",".join(f"0x{b:02x}" for b in data[offset:offset + 16]) + ",")
    lines.append("};")
lines.append("static const struct { const char *name; const uint8_t *bytes; size_t size; } qemu_fixtures[] = {")
for i, path in enumerate(files):
    lines.append(f'{{"{path.name}", fixture_{i}, sizeof(fixture_{i})}},')
lines.append("};\n")
header = generated / "qemu_fixtures.inc"
content = "\n".join(lines)
if not header.exists() or header.read_text() != content:
    header.write_text(content)
env.Append(CPPPATH=[str(generated)])
env.BuildSources("$BUILD_DIR/qemu-tests", "$PROJECT_DIR/test/qemu")
