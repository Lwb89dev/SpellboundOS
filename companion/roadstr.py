"""Notification-to-turn-by-turn parser for Roadstr navigation notifications.

Parses English and Italian turn-by-turn navigation notification text into
structured NavInstruction records for SpellboundFit's PROTO_NAV_UPDATE frames.
"""
from dataclasses import dataclass
import re

from companion.protocol import NavManeuver, encode_nav_update


@dataclass(frozen=True)
class NavInstruction:
    maneuver: NavManeuver
    distance_m: int
    eta_min: int
    street: str
    next_street: str = ''
    roundabout_exit: int = 0

    def to_frame(self, seq: int) -> bytes:
        return encode_nav_update(
            seq=seq,
            maneuver=self.maneuver,
            distance_m=self.distance_m,
            eta_min=self.eta_min,
            street=self.street,
            next_street=self.next_street,
            roundabout_exit=self.roundabout_exit,
        )


_DIST_RE = re.compile(r'(\d+(?:[.,]\d+)?)\s*(km|m)\b', re.IGNORECASE)
_ETA_RE = re.compile(r'(?:eta|arrivo)[^0-9]*(\d+)\s*(?:min|m\b)', re.IGNORECASE)
_EXIT_RE = re.compile(r'(\d+)(?:st|nd|rd|th|a|°)?\s*(?:exit|uscita)', re.IGNORECASE)
_STREET_RE = re.compile(r'\b(?:onto|on|su|verso|towards?)\s+([^•|\n()]+)', re.IGNORECASE)


def _detect_maneuver(text: str) -> NavManeuver:
    low = text.lower()
    if any(k in low for k in ('arrived', 'destination', 'arrivato', 'destinazione')):
        return NavManeuver.ARRIVE
    if any(k in low for k in ('roundabout', 'rotonda', 'rotatoria')):
        return NavManeuver.ROUNDABOUT
    if any(k in low for k in ('u-turn', 'inversione')):
        return NavManeuver.UTURN
    if any(k in low for k in ('sharp left', 'stretta a sinistra')):
        return NavManeuver.SHARP_LEFT
    if any(k in low for k in ('slight left', 'leggermente a sinistra', 'tieni la sinistra')):
        return NavManeuver.SLIGHT_LEFT
    if any(k in low for k in ('left', 'sinistra')):
        return NavManeuver.LEFT
    if any(k in low for k in ('sharp right', 'stretta a destra')):
        return NavManeuver.SHARP_RIGHT
    if any(k in low for k in ('slight right', 'leggermente a destra', 'tieni la destra')):
        return NavManeuver.SLIGHT_RIGHT
    if any(k in low for k in ('right', 'destra')):
        return NavManeuver.RIGHT
    if any(k in low for k in ('straight', 'continue', 'prosegui', 'dritto')):
        return NavManeuver.STRAIGHT
    return NavManeuver.NONE


def parse_roadstr_notification(title: str, body: str) -> NavInstruction | None:
    """Parse a Roadstr / navigation notification into a NavInstruction, or None."""
    combined = f'{title} {body}'.strip()
    maneuver = _detect_maneuver(combined)
    if maneuver == NavManeuver.NONE:
        return None

    distance_m = 0
    dm = _DIST_RE.search(combined)
    if dm:
        val = float(dm.group(1).replace(',', '.'))
        unit = dm.group(2).lower()
        distance_m = int(round(val * 1000)) if unit == 'km' else int(round(val))

    eta_min = 0
    em = _ETA_RE.search(combined)
    if em:
        eta_min = int(em.group(1))

    roundabout_exit = 0
    if maneuver == NavManeuver.ROUNDABOUT:
        xm = _EXIT_RE.search(combined)
        if xm:
            roundabout_exit = int(xm.group(1))

    street = ''
    sm = _STREET_RE.search(body) or _STREET_RE.search(title)
    if sm:
        street = sm.group(1).strip(' -.,:')
        # Trim trailing ETA clause if present
        street = re.sub(r'\s*(?:eta|arrivo)\b.*$', '', street, flags=re.IGNORECASE).strip(' -.,:')
    if not street:
        street = title.strip()[:63]

    return NavInstruction(
        maneuver=maneuver,
        distance_m=distance_m,
        eta_min=eta_min,
        street=street[:63],
        roundabout_exit=roundabout_exit,
    )
