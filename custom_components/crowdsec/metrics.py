"""Lean parser for the Prometheus text format.

Deliberately without an external dependency: under ``/metrics`` CrowdSec only
returns simple counters and gauges, so a full Prometheus client would be
needless ballast for the integration.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

_ESCAPES = {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}


@dataclass(frozen=True, slots=True)
class Sample:
    """A single metric sample: labels plus value."""

    labels: dict[str, str] = field(hash=False)
    value: float


def _parse_labels(raw: str) -> dict[str, str]:
    """Split the content between the curly braces.

    Commas and quotes may appear inside label values (escaped), so a simple
    ``split(",")`` is not enough.
    """
    labels: dict[str, str] = {}
    index = 0
    length = len(raw)

    while index < length:
        while index < length and raw[index] in ", ":
            index += 1
        start = index
        while index < length and raw[index] != "=":
            index += 1
        if index >= length:
            break
        key = raw[start:index].strip()
        index += 1  # skip '='
        while index < length and raw[index] == " ":
            index += 1
        if index >= length or raw[index] != '"':
            break
        index += 1

        buffer: list[str] = []
        while index < length and raw[index] != '"':
            if raw[index] == "\\" and index + 1 < length:
                buffer.append(_ESCAPES.get(raw[index + 1], raw[index + 1]))
                index += 2
                continue
            buffer.append(raw[index])
            index += 1
        index += 1  # closing '"'

        if key:
            labels[key] = "".join(buffer)

    return labels


def parse_prometheus(text: str) -> dict[str, list[Sample]]:
    """Parse a Prometheus text body into ``{metric_name: [Sample, ...]}``."""
    result: dict[str, list[Sample]] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        brace = line.find("{")
        if brace == -1:
            parts = line.split()
            if len(parts) < 2:
                continue
            name, labels, raw_value = parts[0], {}, parts[1]
        else:
            end = line.rfind("}")
            if end < brace:
                continue
            name = line[:brace].strip()
            labels = _parse_labels(line[brace + 1 : end])
            rest = line[end + 1 :].split()
            if not rest:
                continue
            raw_value = rest[0]

        if not name:
            continue
        try:
            value = float(raw_value)
        except ValueError:
            continue

        result.setdefault(name, []).append(Sample(labels, value))

    return result


class MetricSet:
    """Convenient access to a parsed metric set."""

    def __init__(self, samples: dict[str, list[Sample]]) -> None:
        self._samples = samples

    def __contains__(self, name: str) -> bool:
        return name in self._samples

    def samples(self, name: str) -> list[Sample]:
        """All samples of a metric (empty list if unknown)."""
        return self._samples.get(name, [])

    def total(
        self, name: str, predicate: Callable[[Sample], bool] | None = None
    ) -> float | None:
        """Sum of all samples of a metric, ``None`` if not present."""
        samples = self._samples.get(name)
        if samples is None:
            return None
        if predicate is not None:
            samples = [s for s in samples if predicate(s)]
        return float(sum(s.value for s in samples))

    def first_total(self, names: Iterable[str]) -> float | None:
        """Sum of the first metric from ``names`` that is present."""
        for name in names:
            value = self.total(name)
            if value is not None:
                return value
        return None

    def single(self, name: str) -> float | None:
        """Value of a metric without labels (e.g. ``process_start_time_seconds``)."""
        samples = self._samples.get(name)
        if not samples:
            return None
        return samples[0].value

    def group_sum(self, name: str, label: str) -> dict[str, float]:
        """Sum up the samples of a metric grouped by a label."""
        grouped: dict[str, float] = {}
        for sample in self._samples.get(name, []):
            key = sample.labels.get(label, "")
            grouped[key] = grouped.get(key, 0.0) + sample.value
        return grouped

    def as_dict(self, prefix: str = "") -> dict[str, list[dict[str, object]]]:
        """Serialisable view for the diagnostics data.

        ``prefix`` filters down to the interesting metrics — alongside them the
        endpoint also returns the complete Go runtime, which helps nobody.
        """
        return {
            name: [
                {"labels": sample.labels, "value": sample.value} for sample in samples
            ]
            for name, samples in self._samples.items()
            if name.startswith(prefix)
        }

    def label_of(self, name: str, label: str) -> str | None:
        """Label value of the first sample, e.g. the version from ``cs_info``."""
        for sample in self._samples.get(name, []):
            if label in sample.labels:
                return sample.labels[label]
        return None
