import struct
from pathlib import Path

base = Path("C:/Users/pramp/Downloads/begghia/akaka/ui/src-tauri/icons")
base.mkdir(parents=True, exist_ok=True)

width = 16
height = 16
bpp = 32

reserved = 0
type_ = 1
count = 1
icon_dir = struct.pack('<HHH', reserved, type_, count)

color_count = 0
reserved2 = 0
planes = 1
bit_count = bpp

header_size = 40
bmp_width = width
bmp_height = height * 2
planes_bmp = 1
bit_count_bmp = bpp
compression = 0
size_image = width * height * 4
xppm = 0
yppm = 0
clr_used = 0
clr_important = 0
bmp_header = struct.pack('<IIIHHIIIIII', header_size, bmp_width, bmp_height,
                         planes_bmp, bit_count_bmp, compression, size_image,
                         xppm, yppm, clr_used, clr_important)

color = bytes([0x2a, 0x4f, 0xd3, 0xff])
row = color * width
pixel_data = row * height

and_row = b'\x00\x00\x00\x00'
and_mask = and_row * height

image_data = bmp_header + pixel_data + and_mask
bytes_in_res = len(image_data)
image_offset = len(icon_dir) + 16

entry = struct.pack('<BBBBHHII', width, height, color_count, reserved2,
                    planes, bit_count, bytes_in_res, image_offset)

ico_data = icon_dir + entry + image_data

out = base / 'icon.ico'
out.write_bytes(ico_data)
print(f"Wrote {out} ({len(ico_data)} bytes)")
