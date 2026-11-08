"""A8 SLA hesaplamasi (master_prompt.md 6): "severity/KEV'e gore config'den
tanimlanan hedef sureler (sirket politikasi belirler; kodda sabit rakam
yok), due_date, gecikenler listesi".

Bu modul SAF FONKSIYONLARDAN olusur (core/finding_model.py ile ayni desen):
DB/ORM baglantisi yok, sadece ilkel degerler alir. "Kodda sabit rakam yok"
kuralini DEFAULT_SLA_DAYS'in SADECE bir baslangic degeri olmasi, admin
panelden (app/routes_settings.py -> core.models.Setting) HER ZAMAN
degistirilebilmesiyle karsiliyoruz -- hesaplama fonksiyonu degerleri asla
kendisi uretmez, cagirandan alir."""

from __future__ import annotations

import datetime as dt
from typing import Mapping, Optional

SLA_SETTINGS_KEY = "sla_days"

# master_prompt.md 6 A8: "sirket politikasi belirler; kodda sabit rakam
# yok" -- bu sadece hic ayar yapilmamis bir sistemde makul bir BASLANGIC
# noktasi, admin panelden (/settings) herhangi bir an degistirilebilir.
DEFAULT_SLA_DAYS: Mapping[str, int] = {
    "kev": 1,
    "cvss_9": 3,
    "cvss_7": 14,
    "cvss_4": 60,
    "default": 90,
}


def _tier_for(kev: bool, cvss_score: Optional[float]) -> str:
    if kev:
        return "kev"
    if cvss_score is not None:
        if cvss_score >= 9:
            return "cvss_9"
        if cvss_score >= 7:
            return "cvss_7"
        if cvss_score >= 4:
            return "cvss_4"
    return "default"


def compute_due_date(
    *, kev: bool, cvss_score: Optional[float], first_seen_at: dt.datetime, sla_days: Mapping[str, int]
) -> dt.date:
    """master_prompt.md 4.6 siralamasiyla AYNI oncelik: KEV > CVSS esigi.
    `sla_days` eksik bir tier icerirse DEFAULT_SLA_DAYS'teki karsiligina
    duser (kismi/eski bir ayar kaydi sistemi kirmasin)."""
    tier = _tier_for(kev, cvss_score)
    days = sla_days.get(tier, DEFAULT_SLA_DAYS[tier])
    return first_seen_at.date() + dt.timedelta(days=days)


def is_overdue(due_date: dt.date, today: Optional[dt.date] = None) -> bool:
    today = today or dt.datetime.now(dt.timezone.utc).date()
    return today > due_date


def days_remaining(due_date: dt.date, today: Optional[dt.date] = None) -> int:
    """Negatif deger = kac gun GECIKMIS."""
    today = today or dt.datetime.now(dt.timezone.utc).date()
    return (due_date - today).days


def merged_sla_days(stored_value: Optional[Mapping[str, int]]) -> dict[str, int]:
    """Ayarlar tablosunda kismi/eksik bir deger olsa bile her tier icin
    bir deger garanti eder (DEFAULT_SLA_DAYS ile birlestirir)."""
    merged = dict(DEFAULT_SLA_DAYS)
    if stored_value:
        for key, value in stored_value.items():
            if key in merged and isinstance(value, int) and value > 0:
                merged[key] = value
    return merged
