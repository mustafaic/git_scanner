"""app/chart_helpers.py testleri -- DB/config gerektirmez (saf fonksiyonlar,
sadece sayisal geometri uretir). Analiz sayfasinin (app/routes_analytics.py)
donut/trend/bar grafiklerinin dogru hesaplandigini dogrular."""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.chart_helpers import (  # noqa: E402
    bar_percentages,
    daily_open_counts,
    donut_segments,
    trend_polyline_points,
)


def test_donut_segments_splits_full_circle_proportionally():
    segments = donut_segments([3.0, 1.0])
    assert [s.pct for s in segments] == [75.0, 25.0]
    # Toplam cember (2*pi*40) iki segmentin dash_array uzunluklarina esit dagilmali.
    import math

    circumference = 2 * math.pi * 40.0
    first_len = float(segments[0].dash_array.split(" ")[0])
    second_len = float(segments[1].dash_array.split(" ")[0])
    assert abs(first_len - circumference * 0.75) < 0.01
    assert abs(second_len - circumference * 0.25) < 0.01
    # Ikinci segment ilkinin uzunlugundan sonra baslar (dashoffset negatif, kumulatif).
    assert segments[1].dash_offset == -first_len


def test_donut_segments_empty_when_total_is_zero():
    assert donut_segments([0, 0, 0]) == []
    assert donut_segments([]) == []


def test_bar_percentages_relative_to_peak():
    assert bar_percentages([10, 5, 0, 20]) == [50.0, 25.0, 0.0, 100.0]


def test_bar_percentages_all_zero_or_empty_does_not_raise():
    assert bar_percentages([0, 0]) == [0.0, 0.0]
    assert bar_percentages([]) == []


def test_trend_polyline_points_empty_series():
    assert trend_polyline_points([]) == ""


def test_trend_polyline_points_single_value_draws_flat_line():
    points = trend_polyline_points([5], width=600.0, height=160.0, padding=8.0)
    xs_ys = [p.split(",") for p in points.split(" ")]
    assert len(xs_ys) == 2
    assert xs_ys[0][1] == xs_ys[1][1]  # yatay bir cizgi (ayni y)


def test_trend_polyline_points_peak_is_at_top():
    # SVG'de y ekseni ters -- en yuksek deger en KUCUK y koordinatina sahip olmali.
    points = trend_polyline_points([1, 5, 1], width=100.0, height=100.0, padding=0.0)
    ys = [float(p.split(",")[1]) for p in points.split(" ")]
    assert ys[1] < ys[0]
    assert ys[1] < ys[2]


def test_daily_open_counts_basic_window():
    start = dt.date(2026, 1, 1)
    rows = [
        (dt.date(2026, 1, 1), dt.date(2026, 1, 3)),  # 1 ve 2'de acik, 3'te kapali
        (dt.date(2025, 12, 20), None),  # pencereden once acildi, hala acik
    ]
    counts = daily_open_counts(rows, start, 7)
    assert counts == [2, 2, 1, 1, 1, 1, 1]


def test_daily_open_counts_opened_and_closed_same_day_never_counted():
    start = dt.date(2026, 1, 1)
    rows = [(dt.date(2026, 1, 5), dt.date(2026, 1, 5))]
    counts = daily_open_counts(rows, start, 7)
    assert counts == [0, 0, 0, 0, 0, 0, 0]


def test_daily_open_counts_empty_window_returns_empty_list():
    assert daily_open_counts([], dt.date(2026, 1, 1), 0) == []
