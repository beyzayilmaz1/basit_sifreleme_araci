"""
Hassas veri keşfi (öğrenme / demo ölçeği).

OpenText Voltage tarzı "önce keşfet, sonra koru" fikrinin JR karşılığı:
kurumsal discovery motoru değil; açıklanabilir regex + rapor.

Önemli: bulguların kendisi (ham PII) varsayılan olarak diske yazılmaz;
yalnızca tip, konum ve örnek maskelenmiş özet döner.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

# Metin olarak taranacak uzantılar (binary taramak false-positive üretir).
DEFAULT_TEXT_SUFFIXES = {
    ".txt",
    ".csv",
    ".json",
    ".md",
    ".log",
    ".yml",
    ".yaml",
    ".xml",
    ".ini",
    ".cfg",
    ".env",
    ".sql",
}

# İsim → (regex, açıklama). Regex'ler eğitim amaçlıdır; üretim DLP değildir.
_PATTERNS: dict[str, tuple[re.Pattern[str], str]] = {
    "email": (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "E-posta adresi",
    ),
    "iban_tr": (
        re.compile(r"\bTR\d{2}\s?(?:\d{4}\s?){4}\d{4}\s?\d{2}\b", re.IGNORECASE),
        "Türkiye IBAN",
    ),
    "tckn": (
        # 11 haneli sayı; checksum doğrulanmaz (demo keşfi).
        re.compile(r"\b[1-9]\d{10}\b"),
        "TC kimlik benzeri (11 hane)",
    ),
    "card": (
        # 13–19 hane; boşluk/tire. IBAN satırlarında false-positive olabilir —
        # _card_allowed ile TR/IBAN bağlamı elenir.
        re.compile(r"(?<![A-Za-z0-9])(?:\d[ -]*?){13,19}(?!\d)"),
        "Kart numarası benzeri",
    ),
    "phone_tr": (
        re.compile(r"\b(?:\+90|0)?\s?5\d{2}\s?\d{3}\s?\d{2}\s?\d{2}\b"),
        "TR cep telefonu benzeri",
    ),
}


def _card_allowed(line: str, match: re.Match[str]) -> bool:
    """IBAN / TR bağlamındaki rakam dizilerini kart sayma."""
    if not _looks_like_card(match.group(0)):
        return False
    iban_pat = _PATTERNS["iban_tr"][0]
    for iban in iban_pat.finditer(line):
        # Kart adayı IBAN aralığıyla örtüşüyorsa false-positive.
        if match.start() < iban.end() and match.end() > iban.start():
            return False
    window = line[max(0, match.start() - 4) : match.end() + 1]
    if re.search(r"TR\d", window, re.IGNORECASE):
        return False
    if "iban" in line.lower():
        return False
    return True


@dataclass(frozen=True)
class Finding:
    """Tek bir eşleşme (maskelenmiş)."""

    path: str
    kind: str
    line: int
    masked: str
    description: str


@dataclass(frozen=True)
class ScanReport:
    """Klasör taraması özeti."""

    root: str
    files_scanned: int
    files_with_findings: int
    finding_count: int
    by_kind: dict[str, int]
    findings: list[Finding]

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_with_findings": self.files_with_findings,
            "finding_count": self.finding_count,
            "by_kind": dict(self.by_kind),
            "findings": [asdict(f) for f in self.findings],
        }


def mask_secret(value: str, *, keep: int = 2) -> str:
    """PII'yi log/raporda göstermek için maskele."""
    cleaned = re.sub(r"\s+", "", value)
    if len(cleaned) <= keep * 2:
        return "*" * len(cleaned)
    return cleaned[:keep] + ("*" * (len(cleaned) - keep * 2)) + cleaned[-keep:]


def _looks_like_card(candidate: str) -> bool:
    digits = re.sub(r"\D", "", candidate)
    return 13 <= len(digits) <= 19


def iter_text_files(root: Path, suffixes: set[str] | None = None) -> list[Path]:
    """root altındaki metin dosyalarını listeler (symlink takip etmez)."""
    allowed = suffixes or DEFAULT_TEXT_SUFFIXES
    root = root.resolve()
    if root.is_file():
        return [root] if root.suffix.lower() in allowed or root.suffix == "" else []
    if not root.is_dir():
        return []
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in allowed:
            continue
        # Şifreli paketleri tekrar tarama.
        if path.suffix.lower() == ".bsa":
            continue
        out.append(path)
    return out


def scan_text(text: str, *, path: str = "<memory>") -> list[Finding]:
    """Tek metin bloğunu tara."""
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for kind, (pattern, description) in _PATTERNS.items():
            for match in pattern.finditer(line):
                raw = match.group(0)
                if kind == "card" and not _card_allowed(line, match):
                    continue
                # TCKN: kart/telefon false-positive azalt — yalnız 11 hane.
                if kind == "tckn" and len(re.sub(r"\D", "", raw)) != 11:
                    continue
                findings.append(
                    Finding(
                        path=path,
                        kind=kind,
                        line=line_no,
                        masked=mask_secret(raw),
                        description=description,
                    )
                )
    return findings


def scan_path(
    root: Path,
    *,
    suffixes: set[str] | None = None,
    max_file_bytes: int = 2 * 1024 * 1024,
) -> ScanReport:
    """
    Dosya veya klasör tarar.

    max_file_bytes: tek dosya üst sınırı (DoS / yanlışlıkla devasa log).
    """
    files = iter_text_files(root, suffixes=suffixes)
    all_findings: list[Finding] = []
    files_with = 0
    by_kind: dict[str, int] = {}

    for path in files:
        try:
            size = path.stat().st_size
            if size > max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found = scan_text(text, path=str(path))
        if found:
            files_with += 1
            all_findings.extend(found)
            for item in found:
                by_kind[item.kind] = by_kind.get(item.kind, 0) + 1

    return ScanReport(
        root=str(root.resolve()),
        files_scanned=len(files),
        files_with_findings=files_with,
        finding_count=len(all_findings),
        by_kind=by_kind,
        findings=all_findings,
    )


def files_needing_protection(report: ScanReport) -> list[Path]:
    """En az bir bulgu içeren benzersiz dosya yolları."""
    seen: set[str] = set()
    paths: list[Path] = []
    for finding in report.findings:
        if finding.path in seen:
            continue
        seen.add(finding.path)
        paths.append(Path(finding.path))
    return paths
