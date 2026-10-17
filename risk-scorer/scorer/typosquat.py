from __future__ import annotations
import json
import os
from typing import Dict, List, Optional, Tuple
from .models import RiskFactor

# Keyboard adjacency map for QWERTY keyboards
KEYBOARD_ADJACENCY: Dict[str, str] = {
    "q": "wased", "w": "qasde", "e": "wsdfr", "r": "edfgt", "t": "rfghy", "y": "tghju",
    "u": "yhjki", "i": "ujklo", "o": "iklp", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhvb", "h": "gyujnb",
    "j": "huikmn", "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
    "-": "_", "_": "-", ".": "-",
}

# Homoglyphs and visually identical characters
HOMOGLYPHS: Dict[str, List[str]] = {
    "l": ["1", "i", "I", "|"],
    "1": ["l", "i"],
    "0": ["o", "O"],
    "o": ["0"],
    "m": ["rn", "nn"],
    "rn": ["m"],
    "vv": ["w"],
    "w": ["vv"],
    "d": ["cl"],
    "cl": ["d"],
}


def damerau_levenshtein(s1: str, s2: str) -> int:
    """Compute Damerau-Levenshtein distance between two strings."""
    d: Dict[Tuple[int, int], int] = {}
    len1, len2 = len(s1), len(s2)

    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost,  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + cost)  # transposition

    return d[(len1 - 1, len2 - 1)]


def normalize_name(name: str) -> str:
    """Strip scope prefix and normalize delimiters."""
    clean = name.lower()
    if clean.startswith("@"):
        parts = clean.split("/", 1)
        if len(parts) == 2:
            clean = parts[1]
    return clean.replace("-", "").replace("_", "").replace(".", "")


class TyposquatDetector:
    def __init__(self, top_packages_path: Optional[str] = None):
        if not top_packages_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            top_packages_path = os.path.join(base_dir, "data", "top_packages.json")

        self.top_packages: Dict[str, List[str]] = {"npm": [], "pypi": [], "go": []}
        if os.path.exists(top_packages_path):
            with open(top_packages_path, "r", encoding="utf-8") as f:
                self.top_packages = json.load(f)

    def analyze(self, name: str, ecosystem: str) -> List[RiskFactor]:
        factors: List[RiskFactor] = []
        popular = self.top_packages.get(ecosystem.lower(), [])
        norm_input = normalize_name(name)
        lower_input = name.lower()

        # If name is already in the top packages list, it's legitimate
        for pop in popular:
            pop_lower = pop.lower()
            if pop_lower.startswith("@"):
                pop_lower = pop_lower.split("/", 1)[-1]
            if pop.lower() == lower_input or pop_lower == lower_input:
                return []

        for pop in popular:
            pop_clean = pop.lower()
            if pop_clean.startswith("@"):
                pop_clean = pop_clean.split("/", 1)[-1]
            if "/" in pop_clean:
                pop_clean = pop_clean.split("/")[-1]

            norm_pop = normalize_name(pop_clean)

            # 1. Separator and delimiter trick (e.g. cross-env vs crossenv)
            if norm_input == norm_pop and lower_input != pop.lower():
                factors.append(RiskFactor(
                    category="typosquatting",
                    name="separator_trick",
                    score_delta=80,
                    severity="CRITICAL",
                    evidence=f"Exact match on normalized name with top package '{pop}' using delimiter variation",
                    remediation=f"Verify if intended package was the popular upstream '{pop}'",
                ))
                continue

            # 2. Damerau-Levenshtein distance 1 (1 edit difference from popular package)
            dist = damerau_levenshtein(lower_input, pop_clean)
            if dist == 1 and len(pop_clean) >= 4:
                factors.append(RiskFactor(
                    category="typosquatting",
                    name="damerau_levenshtein_distance_1",
                    score_delta=85,
                    severity="CRITICAL",
                    evidence=f"Damerau-Levenshtein edit distance of 1 from top downloaded package '{pop}' ({lower_input} vs {pop_clean})",
                    remediation=f"Did you mean '{pop}'? Typosquatting of critical packages is a high-risk vector.",
                ))
                continue

            # 3. Damerau-Levenshtein distance 2 for long names
            if dist == 2 and len(pop_clean) >= 7:
                factors.append(RiskFactor(
                    category="typosquatting",
                    name="damerau_levenshtein_distance_2",
                    score_delta=45,
                    severity="HIGH",
                    evidence=f"Close edit distance (2) from popular package '{pop}'",
                    remediation=f"Confirm package identity against upstream '{pop}'",
                ))

            # 4. Homoglyphs
            if self._check_homoglyph(lower_input, pop_clean):
                factors.append(RiskFactor(
                    category="typosquatting",
                    name="homoglyph_substitution",
                    score_delta=90,
                    severity="CRITICAL",
                    evidence=f"Visual homoglyph substitution detected targeting popular package '{pop}'",
                    remediation=f"Target package attempts visual deception of '{pop}'",
                ))

        return factors

    def _check_homoglyph(self, s1: str, s2: str) -> bool:
        if s1 == s2:
            return False
        for original, glyphs in HOMOGLYPHS.items():
            for g in glyphs:
                if original in s2 and g in s1:
                    test_str = s1.replace(g, original)
                    if test_str == s2:
                        return True
        return False
