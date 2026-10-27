#!/usr/bin/env python3
"""Generate pingrail's colour tokens and write them into src/web/app.css.

    python3 packaging/tools/palette/generate.py packaging/tools/palette/night-rail.json --write src/web/app.css

Without --write it prints the CSS. The output is the same on every run (the
search uses fixed seeds), and nothing is written if a check fails.

How the colours are chosen:

  - Surfaces (page, panel, sidebar, hover, selected) are fixed in the concept
    file as OKLCH tints of the logo blue.
  - Inks are found by contrast target, Leonardo-style: the lightest (or, in the
    dark theme, darkest) ink that still clears its WCAG target on every surface
    it can sit on, so no text drops below 4.5:1 anywhere.
  - The data colours (good, warn, crit, live, and the average line) come from
    simulated annealing on a weighted loss, in the spirit of Ström's
    category-colors: ΔE in OKLab between every pair, in normal vision and under
    simulated protanopia, deuteranopia and tritanopia (Machado et al. 2009,
    severity 1, in linear sRGB); lightness steps between good, warn and crit so
    they survive greyscale; WCAG contrast of each mark on the surface it is
    drawn on; text on the loss colour; the average line kept apart from the
    interface blue; chroma rewarded relative to the sRGB gamut boundary at that
    lightness and hue (nutelch's relative chroma), so every colour is in gamut
    by construction; each hue held inside its role's window.
  - The route zones are a severity ramp: the quietest tints that clear the page
    and each other by ΔE_OK 0.05, step in lightness, and keep the line and
    whiskers drawn over them at 3:1 (WCAG 1.4.11).

Copyright (C) 2026 Ulrich Holtzhausen. Apache-2.0.
"""
import json, math, random, sys

# ---------------------------------------------------------------- colour maths


def srgb_to_lin(c):
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def lin_to_srgb(c):
    return 12.92 * c if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055


def oklch_to_lin(L, C, h):
    a, b = C * math.cos(math.radians(h)), C * math.sin(math.radians(h))
    l_ = L + 0.3963377774 * a + 0.2158037573 * b
    m_ = L - 0.1055613458 * a - 0.0638541728 * b
    s_ = L - 0.0894841775 * a - 1.2914855480 * b
    l, m, s = l_ ** 3, m_ ** 3, s_ ** 3
    return (4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
            -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
            -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s)


def lin_to_oklab(r, g, b):
    l = 0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b
    m = 0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b
    s = 0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b
    l_, m_, s_ = (math.copysign(abs(v) ** (1 / 3), v) for v in (l, m, s))
    return (0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_,
            1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_,
            0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_)


def in_gamut(lin, eps=1e-6):
    return all(-eps <= v <= 1 + eps for v in lin)


_maxc = {}


def max_chroma(L, h):
    """Largest chroma inside sRGB at this lightness and hue (bisection)."""
    key = (round(L, 4), round(h, 2))
    if key in _maxc:
        return _maxc[key]
    lo, hi = 0.0, 0.5
    for _ in range(22):
        mid = (lo + hi) / 2
        if in_gamut(oklch_to_lin(L, mid, h)):
            lo = mid
        else:
            hi = mid
    _maxc[key] = lo
    return lo


class Col:
    """A colour held as OKLCH, in sRGB gamut."""
    __slots__ = ("L", "C", "h", "lin", "lab")

    def __init__(self, L, C, h):
        self.L, self.C, self.h = L, min(C, max_chroma(L, h)), h % 360
        self.lin = tuple(min(1.0, max(0.0, v)) for v in oklch_to_lin(self.L, self.C, self.h))
        self.lab = lin_to_oklab(*self.lin)

    @classmethod
    def rel(cls, L, r, h):
        return cls(L, r * max_chroma(L, h), h)

    @classmethod
    def hex(cls, s):
        s = s.lstrip("#")
        lin = [srgb_to_lin(int(s[i:i + 2], 16) / 255) for i in (0, 2, 4)]
        L, a, b = lin_to_oklab(*lin)
        return cls(L, math.hypot(a, b), math.degrees(math.atan2(b, a)))

    def to_hex(self):
        return "#" + "".join(f"{round(lin_to_srgb(v) * 255):02x}" for v in self.lin)

    def css(self):
        return f"oklch({self.L * 100:.1f}% {self.C:.3f} {self.h:.0f})"

    @property
    def Y(self):
        r, g, b = self.lin
        return 0.2126 * r + 0.7152 * g + 0.0722 * b


def mix(a, b, t):
    """t of a over b, in linear light (what compositing does)."""
    lin = tuple(a.lin[i] * t + b.lin[i] * (1 - t) for i in range(3))
    L, A, B = lin_to_oklab(*lin)
    return Col(L, math.hypot(A, B), math.degrees(math.atan2(B, A)))


def wcag(a, b):
    y1, y2 = sorted((a.Y, b.Y), reverse=True)
    return (y1 + 0.05) / (y2 + 0.05)


def apca(text, bg):
    """APCA-W3 0.0.98G Lc (positive: dark on light; negative: light on dark)."""
    def Y(c):
        r, g, b = (lin_to_srgb(v) for v in c.lin)
        y = 0.2126729 * r ** 2.4 + 0.7151522 * g ** 2.4 + 0.0721750 * b ** 2.4
        return y if y > 0.022 else y + (0.022 - y) ** 1.414
    yt, yb = Y(text), Y(bg)
    if abs(yb - yt) < 0.0005:
        return 0.0
    if yb > yt:
        s = (yb ** 0.56 - yt ** 0.57) * 1.14
        return 0.0 if s < 0.1 else (s - 0.027) * 100
    s = (yb ** 0.65 - yt ** 0.62) * 1.14
    return 0.0 if s > -0.1 else (s + 0.027) * 100


def de(a, b):
    return math.dist(a.lab, b.lab)


MACHADO = {
    "protan": ((0.152286, 1.052583, -0.204868), (0.114503, 0.786281, 0.099216), (-0.003882, -0.048116, 1.051998)),
    "deutan": ((0.367322, 0.860646, -0.227968), (0.280085, 0.672501, 0.047413), (-0.011820, 0.042940, 0.968881)),
    "tritan": ((1.255528, -0.076749, -0.178779), (-0.078411, 0.930809, 0.147602), (0.004733, 0.691367, 0.303900)),
}


def cvd_lab(c, kind):
    m = MACHADO[kind]
    lin = tuple(min(1.0, max(0.0, sum(m[i][j] * c.lin[j] for j in range(3)))) for i in range(3))
    return lin_to_oklab(*lin)


def de_cvd(a, b, kind):
    return math.dist(cvd_lab(a, kind), cvd_lab(b, kind))


def hinge(v, target):
    return max(0.0, target - v) / target


# ------------------------------------------------------------ surfaces & inks

BRAND = Col.hex("#004e89")      # the logo blue: ink of the light theme
CREAM = Col.hex("#efefd0")      # the logo's light strokes
DARK_TEXT = Col(0.24, 0.05, BRAND.h)
WHITE = Col(0.99, 0.0, 0)


def ink_for(surfaces, target, h, r, light_theme, lo=0.05, hi=0.97):
    """Lightest (light theme) / darkest (dark theme) ink that keeps WCAG
    `target` against every surface it can sit on."""
    fallback, fb = None, -1.0
    for i in range(400):
        L = hi - (hi - lo) * i / 399 if light_theme else lo + (hi - lo) * i / 399
        c = Col.rel(L, r, h)
        worst = min(wcag(c, s) for s in surfaces)
        if worst >= target:
            return c
        if worst > fb:
            fallback, fb = c, worst
    print(f"  note: target {target}:1 unreachable, best {fb:.2f}:1", file=sys.stderr, flush=True)
    return fallback


def surfaces_for(spec):
    s = {k: Col(*v) for k, v in spec["surfaces"].items()}  # bg, sidebar, panel, hover, selected, side_hover, side_selected
    s["surface"] = s.get("surface", s["panel"])
    return s


# ---------------------------------------------------------------- annealing

ROLES = ["good", "warn", "crit", "live", "series"]


def loss(cols, ctx):
    g, w, c, lv, sr = (cols[k] for k in ROLES)
    bg, panel, ink = ctx["bg"], ctx["panel"], ctx["ink"]
    pen = 0.0
    # 1. separation, normal vision
    pairs = [(a, b) for i, a in enumerate(ROLES) for b in ROLES[i + 1:]]
    for a, b in pairs:
        t = 0.075 if {a, b} == {"good", "live"} else 0.11
        pen += 4.0 * hinge(de(cols[a], cols[b]), t) ** 2
    # 2. separation under colour-vision deficiency
    for kind in MACHADO:
        for a, b in (("good", "warn"), ("good", "crit"), ("warn", "crit"), ("series", "crit"), ("series", "good"), ("series", "warn")):
            pen += 3.0 * hinge(de_cvd(cols[a], cols[b], kind), 0.07) ** 2
    # 3. lightness separation of the status triple (greyscale legibility)
    for a, b in (("good", "warn"), ("good", "crit"), ("warn", "crit")):
        pen += 2.0 * hinge(abs(cols[a].L - cols[b].L), 0.07) ** 2
    # 4. contrast against where each mark is drawn
    pen += 6.0 * hinge(wcag(sr, panel), ctx["series_target"]) ** 2
    pen += 3.0 * hinge(wcag(sr, ctx["band_guess"]), 3.6) ** 2
    pen += 3.0 * hinge(wcag(g, bg), 3.0) ** 2
    pen += 3.0 * hinge(wcag(c, bg), 3.0) ** 2
    pen += 3.0 * hinge(wcag(lv, bg), 3.0) ** 2
    pen += 1.5 * hinge(wcag(w, bg), ctx["warn_target"]) ** 2
    # text on the loss colour (the offline banner) needs 4.6:1, dark or light
    pen += 4.0 * hinge(max(wcag(DARK_TEXT, c), wcag(WHITE, c)), 4.6) ** 2
    if ctx.get("island") is not None:  # status dots also sit on the dark sidebar
        isl = ctx["island"]
        pen += 3.0 * hinge(wcag(g, isl), 3.0) ** 2 + 3.0 * hinge(wcag(c, isl), 3.0) ** 2 + 1.5 * hinge(wcag(w, isl), 3.0) ** 2
    # 5. the average line is not the interface blue
    pen += 4.0 * hinge(de(sr, ink), 0.13) ** 2
    # 6. vivid, but off the gamut edge (relative chroma 0.75–0.96)
    for k in ROLES:
        r = cols[k].C / max(max_chroma(cols[k].L, cols[k].h), 1e-9)
        pen -= (0.9 if k in ("live", "series") else 0.6) * min(r, 0.96)
    # 7. stay near the middle of each hue window
    for k in ROLES:
        lo, hi = ctx["hues"][k]
        mid, half = (lo + hi) / 2, (hi - lo) / 2
        pen += 0.25 * ((cols[k].h - mid) / half) ** 2
    # 8. one family: similar relative chroma across the status triple
    rs = [cols[k].C / max(max_chroma(cols[k].L, cols[k].h), 1e-9) for k in ("good", "warn", "crit")]
    pen += 1.0 * (max(rs) - min(rs)) ** 2
    return pen


def anneal(ctx, seed, iters=9000):
    rnd = random.Random(seed)
    st = {}
    for k in ROLES:
        lo, hi = ctx["hues"][k]
        Llo, Lhi = ctx["L"][k]
        st[k] = [rnd.uniform(Llo, Lhi), rnd.uniform(0.7, 0.95), rnd.uniform(lo, hi)]

    def build(s):
        return {k: Col.rel(*s[k]) for k in ROLES}

    cur = build(st)
    e = loss(cur, ctx)
    best, beste = {k: v[:] for k, v in st.items()}, e
    T0, T1 = 0.6, 0.002
    for i in range(iters):
        T = T0 * (T1 / T0) ** (i / iters)
        k = rnd.choice(ROLES)
        j = rnd.randrange(3)
        old = st[k][j]
        step = (0.04, 0.08, 6.0)[j] * (0.3 + T)
        nv = old + rnd.gauss(0, step)
        lo, hi = (ctx["L"][k], (0.55, 0.97), ctx["hues"][k])[j]
        st[k][j] = min(hi, max(lo, nv))
        cand = build(st)
        ne = loss(cand, ctx)
        if ne < e or rnd.random() < math.exp((e - ne) / T):
            e, cur = ne, cand
            if e < beste:
                best, beste = {kk: v[:] for kk, v in st.items()}, e
        else:
            st[k][j] = old
    return build(best), beste


def optimise(ctx, restarts=8):
    runs = [anneal(ctx, seed) for seed in range(restarts)]
    return min(runs, key=lambda r: r[1])


# ----------------------------------------------------------------- one theme


def theme(spec, mode, hue_lock=None):
    t = spec[mode]
    light = mode == "light"
    S = surfaces_for(t)
    bg, panel, side = S["bg"], S["panel"], S["sidebar"]
    hover, sel = S["hover"], S["selected"]
    side_surf = [side, S["side_hover"], S["side_selected"]]
    island = spec.get("island") and light
    all_surf = [bg, panel, hover, sel, S["surface"]] + ([] if island else side_surf)
    out = {"surfaces": S, "island": island}

    # Inks, by contrast target on every surface they can sit on.
    if light:
        # The logo blue, as long as body text keeps 6.5:1 everywhere.
        ink = BRAND if min(wcag(BRAND, s) for s in all_surf) >= 6.5 else ink_for(all_surf, 7, BRAND.h, 0.95, True)
        ink2 = ink_for(all_surf, 5.6, BRAND.h, 0.72, True)
        ink3 = ink_for(all_surf, 4.6, BRAND.h, 0.55, True)
        field = ink_for([bg, panel, side], 3.2, BRAND.h, 0.4, True)
    else:
        ink = ink_for(all_surf, 10, CREAM.h, 0.16, False)
        ink2 = ink_for(all_surf, 7.0, t["ink2_hue"], 0.18, False)
        ink3 = ink_for(all_surf, 4.8, t["ink2_hue"], 0.14, False)
        field = ink_for([bg, panel, side], 3.2, t["ink2_hue"], 0.12, False)
    out.update(ink=ink, ink2=ink2, ink3=ink3, field=field)
    if island:  # the dark sidebar in the light theme carries its own inks
        out["island_inks"] = {"ink": ink_for(side_surf, 10, CREAM.h, 0.16, False),
                              "ink-2": ink_for(side_surf, 7.0, 250, 0.18, False),
                              "ink-3": ink_for(side_surf, 4.8, 250, 0.14, False),
                              "field": ink_for([side], 3.2, 250, 0.12, False)}

    # A first guess at the band (panel shifted toward the series), so the
    # annealer can hold the line's contrast against it.
    band_guess = Col(panel.L - 0.09 if light else panel.L + 0.09, 0.03, spec["hues"]["series"][0])
    ctx = {"bg": bg, "panel": panel, "ink": ink, "band_guess": band_guess,
           "series_target": 6.0 if light else 7.0, "warn_target": 1.7 if light else 3.0,
           "hues": dict(spec["hues"]), "L": t["L"], "island": side if island else None}
    if hue_lock:  # dark theme keeps the light theme's hues (within a few degrees)
        ctx["hues"] = {k: (v - 4, v + 4) for k, v in hue_lock.items()}
    data, e = optimise(ctx)
    out.update(data)
    out["loss"] = e

    sr = data["series"]
    # Band: a quiet tint of the series hue that the average line clears by 3.6:1.
    for i in range(80):
        dL = 0.03 + i * 0.003
        band = Col(panel.L - dL if light else panel.L + dL, 0.05 if light else 0.045, sr.h)
        if de(band, panel) >= (0.07 if light else 0.06) and wcag(sr, band) >= 3.6:
            break
    out["band"] = band
    # Raw samples: between band and line, distinct from both.
    out["sample"] = Col((sr.L + band.L) / 2 + (0.06 if light else -0.04), sr.C * 0.55, sr.h)
    # Route zones on the canvas: a severity ramp. Good is the quietest tint,
    # crit the loudest; each clears the canvas and every other zone, steps
    # in lightness too (so it survives greyscale), and the line, whiskers and
    # dots drawn over it keep their contrast. Greedy: quietest that qualifies.
    zones, prev_d = {}, -0.006
    need = {"good": 0.035, "warn": 0.05, "crit": 0.06}
    for k in ("good", "warn", "crit"):
        h, best = data[k].h, None
        for di in range(0, 64):
            d = prev_d + 0.006 + di * 0.0025
            for ci in range(0, 80):
                C = (0.03 if light else 0.035) + ci * 0.002   # enough chroma for the hue to read
                z = Col(bg.L - d if light else bg.L + d, C, h)
                if de(z, bg) < need[k] or any(de(z, o) < 0.05 for o in zones.values()):
                    continue
                if wcag(sr, z) < 3.0 or wcag(ink3, z) < 3.0:   # WCAG 1.4.11 non-text
                    continue
                cost = 0.5 * C + 1.5 * d   # colour before darkness: tints, not greys
                if best is None or cost < best[0]:
                    best = (cost, z, d)
                break
        if best is None:
            raise SystemExit(f"no {k} zone fits for {mode}")
        zones[k], prev_d = best[1], best[2]
    out["zones"] = zones
    # Neutral 'now' bars, clearly apart from every zone.
    out["bar"] = Col(bg.L - (0.2 if light else -0.2), 0.02, BRAND.h)
    # Text on vivid fills.
    out["on_signal"] = DARK_TEXT
    out["on_crit"] = max((DARK_TEXT, WHITE), key=lambda t: wcag(t, data["crit"]))
    # Notices, focus and selection: warm tints of the warn hue.
    wh = data["warn"].h
    if light:
        out["attn"] = Col(0.93, 0.055, wh)
        out["focus"] = Col(0.94, 0.03, BRAND.h)    # focus isn't a warning: a cool tint, not amber
        out["select"] = Col(0.88, 0.09, wh)
        out["btn_off"] = Col(0.82, 0.02, BRAND.h)
    else:
        out["attn"] = mix(data["warn"], bg, 0.16)
        out["focus"] = Col(0.31, 0.05, BRAND.h)
        out["select"] = mix(data["warn"], bg, 0.38)
        out["btn_off"] = Col(0.42, 0.03, BRAND.h)
    out["crit_hover"] = Col(data["crit"].L + 0.05, data["crit"].C, data["crit"].h)
    out["accent"] = ink
    out["accent_hover"] = Col(ink.L + (0.08 if light else -0.08), ink.C, ink.h)
    out["accent_ink"] = bg if light else Col(0.2, 0.04, BRAND.h)
    return out


def rgba(c, a):
    r, g, b = (round(lin_to_srgb(v) * 255) for v in c.lin)
    return f"rgb({r} {g} {b} / {a})"


def tokens(th, light):
    S = th["surfaces"]
    ink = th["ink"]
    tk = {
        "bg": S["bg"], "surface": S["surface"], "surface-2": S["hover"], "panel": S["panel"], "sidebar": S["sidebar"],
        "ink": ink, "ink-2": th["ink2"], "ink-3": th["ink3"],
        "line": rgba(ink, 0.14 if light else 0.16), "line-strong": rgba(ink, 0.30 if light else 0.30),
        "field": th["field"], "accent": th["accent"], "accent-ink": th["accent_ink"], "accent-hover": th["accent_hover"],
        "accent-soft": S["selected"], "focus-bg": th["focus"], "select": th["select"],
        "series": th["series"], "band": th["band"], "sample": th["sample"], "bar": th["bar"],
        "gap": rgba(ink, 0.07 if light else 0.06),
        "good": th["good"], "warn": th["warn"], "crit": th["crit"], "crit-hover": th["crit_hover"],
        "live": th["live"], "live-halo": rgba(th["live"], 0.38 if light else 0.45),
        "zone-good": th["zones"]["good"], "zone-warn": th["zones"]["warn"], "zone-crit": th["zones"]["crit"],
        "edge": ink if light else S["bg"],
        "attn": th["attn"], "attn-ink": ink, "on-crit": th["on_crit"], "on-signal": th["on_signal"],
        "btn-off": th["btn_off"], "btn-off-fg": ink,
        "trace-avg": th["series"], "trace-raw": th["sample"], "trace-band": th["band"], "trace-slow": th["attn"],
        "backdrop": "rgb(6 20 38 / 0.45)" if light else "rgb(2 10 20 / 0.62)",
    }
    scope = {"surface-2": S["side_hover"], "accent-soft": S["side_selected"]}
    if th.get("island"):
        ii = th["island_inks"]
        scope.update({"ink": ii["ink"], "ink-2": ii["ink-2"], "ink-3": ii["ink-3"], "field": ii["field"],
                      "line": rgba(ii["ink"], 0.16), "line-strong": rgba(ii["ink"], 0.3), "edge": S["sidebar"],
                      "series": Col(min(0.86, th["series"].L + 0.3), th["series"].C * 0.8, th["series"].h)})
    tk["_scope"] = scope
    return tk


def css_block(tk):
    lines = []
    for k, v in tk.items():
        if k.startswith("_"):
            continue
        if isinstance(v, Col):
            lines.append(f"  --{k}: {v.to_hex()};{' ' * max(1, 14 - len(k) - len(v.to_hex()))}/* {v.css()} */")
        else:
            lines.append(f"  --{k}: {v};")
    return "\n".join(lines)



def scoped(light_scope, dark_theme):
    """The sidebar's tokens in the dark theme: every token the light theme's
    sidebar retunes, set back to the dark theme's own value."""
    d = dict(dark_theme["_scope"])
    for k in light_scope:
        if k not in d:
            d[k] = dark_theme["sidebar"] if k == "edge" else dark_theme[k]
    return d


def check(name, th, tk, light):
    """Hard limits: refuse to write a palette that breaks them."""
    S, bad = th["surfaces"], []
    main = [S["bg"], S["panel"], S["hover"], S["selected"]]
    side = [S["sidebar"], S["side_hover"], S["side_selected"]]
    for ink in ("ink", "ink-2", "ink-3"):
        if min(wcag(tk[ink], s) for s in main) < 4.5:
            bad.append(f"{ink} under 4.5:1 on the page")
        if min(wcag(tk["_scope"].get(ink, tk[ink]), s) for s in side) < 4.5:
            bad.append(f"{ink} under 4.5:1 in the sidebar")
    if wcag(tk["ink"], th["focus"]) < 4.5:
        bad.append("text in a focused field under 4.5:1")
    if wcag(th["series"], S["panel"]) < 4.5:
        bad.append("average line under 4.5:1 on the chart")
    if wcag(th["on_crit"], th["crit"]) < 4.5:
        bad.append("text on the loss colour under 4.5:1")
    z = list(th["zones"].values()) + [S["bg"]]
    if min(de(a, b) for i, a in enumerate(z) for b in z[i + 1:]) < 0.035:
        bad.append("route zones too close")
    for k in ("good", "crit", "live"):
        if wcag(th[k], S["bg"]) < 3:
            bad.append(f"{k} under 3:1 on the page")
    cvd = min(de_cvd(th[a], th[b], kind) for kind in MACHADO for a, b in (("good", "warn"), ("good", "crit"), ("warn", "crit")))
    print(f"{name}: smallest text {min(wcag(tk['ink-3'], s) for s in main):.2f}:1, line {wcag(th['series'], S['panel']):.2f}:1, "
          f"loss text {wcag(th['on_crit'], th['crit']):.2f}:1, status ΔE_OK under CVD {cvd:.3f}", file=sys.stderr)
    return bad


def block(selector, tk, extra=""):
    return f"{selector} {{\n{css_block(tk)}{extra}\n}}\n"


def main():
    args = sys.argv[1:]
    write = None
    if "--write" in args:
        i = args.index("--write")
        write = args[i + 1]
        del args[i:i + 2]
    spec = json.load(open(args[0]))
    lt = theme(spec, "light")
    dk = theme(spec, "dark", hue_lock={k: lt[k].h for k in ROLES})
    tl, td = tokens(lt, True), tokens(dk, False)
    td["_scope"] = scoped(tl["_scope"], {**td, "sidebar": dk["surfaces"]["sidebar"]})
    bad = check("light", lt, tl, True) + check("dark", dk, td, False)
    if bad:
        sys.exit("refusing to write: " + "; ".join(bad))
    brand = "  --deep: #004e89;              /* the logo: icon, favicon, reports */\n  --cream: #efefd0;"
    out = (f"/* palette:begin */\n/* {spec['title']}. Generated by packaging/tools/palette/generate.py\n"
           f"   from {spec['file']}; change that and regenerate rather than editing here. */\n"
           + block(":root", tl, "\n" + brand + "\n  color-scheme: light;")
           + "@media (prefers-color-scheme: dark) {\n  " + block(":root:not([data-theme=\"light\"])", td, "\n  color-scheme: dark;").replace("\n", "\n  ").rstrip() + "\n}\n"
           + block(":root[data-theme=\"dark\"]", td, "\n  color-scheme: dark;")
           + "/* The sidebar: a navy island in the light theme, with its own inks. */\n"
           + block(".targets", tl["_scope"], "\n  color: var(--ink);")
           + "@media (prefers-color-scheme: dark) {\n  " + block(":root:not([data-theme=\"light\"]) .targets", td["_scope"]).replace("\n", "\n  ").rstrip() + "\n}\n"
           + block(":root[data-theme=\"dark\"] .targets", td["_scope"])
           + "/* palette:end */")
    if not write:
        print(out)
        return
    css = open(write).read()
    a, b = css.index("/* palette:begin */"), css.index("/* palette:end */") + len("/* palette:end */")
    open(write, "w").write(css[:a] + out + css[b:])
    print(f"wrote {write}", file=sys.stderr)


if __name__ == "__main__":
    main()
