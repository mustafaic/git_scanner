"""Grafik geometrisi uretimi -- saf fonksiyonlar, IO yok, HTML/metin YOK.

Analiz sayfasi (app/routes_analytics.py) icin donut/cizgi/bar grafiklerin
SAYISAL geometrisini hesaplar. Bilerek hicbir etiket/repo-adi/paket-adi
metni ISLEMEZ -- bu modul SADECE sayi alir, sayi/koordinat doner. Metin
her zaman cagiran template'te normal Jinja auto-escape ile ayri HTML metin
dugumlerinde gosterilir (bkz. docs/THREAT_MODEL.md madde 1: "Jinja2
auto-escape, `|safe` kullanilmiyor" ilkesi -- ham SVG string'ine kullanici
kontrollu metin ASLA gömülmez).

Yeni bagimlilik YOK (sadece stdlib `math`), CSP'de script-src 'self' disinda
hicbir sey gerektirmez -- grafikler sunucu tarafinda uretilen inline SVG'dir.
"""

from __future__ import annotations

import datetime as _dt
import math
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class DonutSegment:
    value: float
    pct: float  # 0-100
    dash_array: str  # SVG stroke-dasharray degeri
    dash_offset: float  # SVG stroke-dashoffset degeri


def donut_segments(values: list[float], *, radius: float = 40.0) -> list[DonutSegment]:
    """Degerleri (sayim) bir donut grafigin stroke-dasharray/dashoffset
    degerlerine cevirir. Caller `<circle r="{radius}" stroke-dasharray=...>`
    seklinde (viewBox 0 0 100 100, merkez 50 50, `transform="rotate(-90 50 50)"`
    ile) sirayla cizer -- segmentler ust noktadan saat yonunde baslar.

    Toplam 0 ise (hic veri yok) bos liste doner -- caller "veri yok" durumunu
    ayrica ele almali.
    """
    total = sum(values)
    if total <= 0:
        return []
    circumference = 2 * math.pi * radius
    segments: list[DonutSegment] = []
    cumulative = 0.0
    for value in values:
        pct = (value / total) * 100
        seg_len = circumference * (value / total)
        segments.append(
            DonutSegment(
                value=value,
                pct=round(pct, 1),
                dash_array=f"{seg_len:.3f} {max(circumference - seg_len, 0):.3f}",
                dash_offset=round(-cumulative, 3),
            )
        )
        cumulative += seg_len
    return segments


def bar_percentages(values: list[float]) -> list[float]:
    """Her degeri, listedeki en buyuk degere oranla 0-100 araliginda bir
    genislik yuzdesine cevirir (yatay bar listesi icin, ör. "en riskli 10
    repo"). Hepsi 0 ise hepsi 0 doner (bar'lar bos gorunur, hata atilmaz)."""
    peak = max(values, default=0)
    if peak <= 0:
        return [0.0 for _ in values]
    return [round((v / peak) * 100, 1) for v in values]


def trend_polyline_points(values: list[float], *, width: float = 600.0, height: float = 160.0, padding: float = 8.0) -> str:
    """Gunluk sayim serisini bir `<polyline points="...">` icin x,y
    koordinat dizisine cevirir. Y ekseni ters cevrilir (SVG'de 0 ustte).
    Tek nokta veya bos seri icin caller ayrica "yeterli veri yok" gostermeli."""
    if not values:
        return ""
    if len(values) == 1:
        y = height - padding
        return f"{padding:.2f},{y:.2f} {width - padding:.2f},{y:.2f}"
    peak = max(values)
    floor = min(values)
    span = (peak - floor) or 1.0
    usable_width = width - 2 * padding
    usable_height = height - 2 * padding
    step = usable_width / (len(values) - 1)
    points = []
    for i, value in enumerate(values):
        x = padding + i * step
        normalized = (value - floor) / span
        y = padding + (1 - normalized) * usable_height
        points.append(f"{x:.2f},{y:.2f}")
    return " ".join(points)


def daily_open_counts(
    rows: list[tuple[_dt.date, Optional[_dt.date]]], start_date: _dt.date, num_days: int
) -> list[int]:
    """`(first_seen_date, closed_date_or_None)` ciftlerinden, `start_date`'ten
    baslayan `num_days` gunluk pencerede her gun icin "o gun acik olan sayi"
    serisini uretir (O(n + num_days), delta/prefix-sum).

    BILINEN YAKLASIKLIK (trend grafigi icin kabul edilebilir, denetim amacli
    DEGIL): "kapanma" burada SADECE tek bir tarih kolonuyla (findings icin
    resolved_at, secret_findings icin rotated_at) temsil ediliyor. Panelden
    elle yapilan FALSE_POSITIVE/ACCEPTED_RISK/NOT_AFFECTED gibi kapanmalar bu
    kolonu DOLDURMAZ (bkz. core/models.py Finding.resolved_at docstring'i --
    o sadece eslestirme motorunun RESOLVED karari icin yazilir) -- bu yuzden
    gercekte kapanmis ama manuel kapatilmis bir bulgu bu trend'de "hala acik"
    gorunebilir. Gunluk/haftalik yon (artiyor mu, azaliyor mu) icin yeterli,
    kesin bir denetim sayisi degil.
    """
    if num_days <= 0:
        return []
    delta = [0] * (num_days + 1)
    for first_seen, closed_at in rows:
        start_idx = max(0, min((first_seen - start_date).days, num_days))
        if closed_at is not None:
            end_idx = max(0, min((closed_at - start_date).days, num_days))
        else:
            end_idx = num_days
        if end_idx <= start_idx:
            continue
        delta[start_idx] += 1
        delta[end_idx] -= 1
    counts: list[int] = []
    running = 0
    for i in range(num_days):
        running += delta[i]
        counts.append(running)
    return counts
