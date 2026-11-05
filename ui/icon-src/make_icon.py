# 사용: python3 ui/icon-src/make_icon.py (Pillow). 결과: src-tauri/icons/icon.ico·icon.png, 미리보기 icon-src/preview.png
# Story Firewall 아이콘(원본): 방패 + 두 점에서 화살표로 이어지는 이야기 경로(유입 → 실행 → 접속).
import math, os
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src-tauri', 'icons')
from PIL import Image, ImageDraw
S = 1024
def shield():
    pts = []
    # 위 가장자리(살짝 둥근 모서리)와 양옆이 아래 끝점으로 휘어 내려가는 곡선
    top, l, r, tip = 90, 140, 884, 960
    pts += [(l + 60, top), (r - 60, top)]
    for i in range(0, 11):  # 오른쪽 위 모서리 둥글게
        a = -math.pi / 2 + (math.pi / 2) * i / 10
        pts.append((r - 60 + 60 * math.cos(a), top + 60 + 60 * math.sin(a)))
    for i in range(0, 41):  # 오른쪽 옆선 → 끝점
        t = i / 40
        x = r - (r - S / 2) * (t ** 2.6)
        y = top + 60 + (tip - top - 60) * t
        pts.append((x, y))
    for i in range(40, -1, -1):  # 왼쪽 옆선 (대칭)
        t = i / 40
        x = l + (S / 2 - l) * (t ** 2.6)
        y = top + 60 + (tip - top - 60) * t
        pts.append((x, y))
    for i in range(0, 11):
        a = math.pi + (math.pi / 2) * i / 10
        pts.append((l + 60 + 60 * math.cos(a), top + 60 + 60 * math.sin(a)))
    return pts
def render(fill, edge, glyph):
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.polygon(shield(), fill=fill)
    a, b, c = (320, 400), (480, 560), (640, 400)
    d.line([a, b, c], fill=glyph, width=90, joint="curve")
    for (x, y) in (a, b):
        d.ellipse([x - 88, y - 88, x + 88, y + 88], fill=glyph)
    # 화살촉(접속 방향)
    ang = math.atan2(c[1] - b[1], c[0] - b[0])
    tip = (c[0] + 150 * math.cos(ang), c[1] + 150 * math.sin(ang))
    w = 125
    p1 = (c[0] + w * math.cos(ang + math.pi / 2), c[1] + w * math.sin(ang + math.pi / 2))
    p2 = (c[0] + w * math.cos(ang - math.pi / 2), c[1] + w * math.sin(ang - math.pi / 2))
    d.polygon([tip, p1, p2], fill=glyph)
    return im
main = render((24, 140, 154, 255), None, (255, 255, 255, 255))
main.save(os.path.join(OUT, "..", "..", "icon-src", "icon-1024.png"))
main.resize((512, 512), Image.LANCZOS).save(os.path.join(OUT, "icon.png"))
main.save(os.path.join(OUT, "icon.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
pv = Image.new("RGBA", (260, 80), (255, 255, 255, 255))
pv.paste((32, 32, 32, 255), (130, 0, 260, 80))
for bg in (0, 130):
    xx = bg + 10
    for s in (16, 24, 32):
        pv.alpha_composite(main.resize((s, s), Image.LANCZOS), (xx, 24)); xx += s + 10
pv.resize((780, 240), Image.NEAREST).save(os.path.join(OUT, "..", "..", "icon-src", "preview.png"))
