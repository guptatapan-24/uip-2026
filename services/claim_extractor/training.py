"""Training utilities for a custom spaCy security NER model."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from services.common.config import ROOT_DIR, load_yaml_config

try:
    import spacy
    from spacy.language import Language
    from spacy.training import Example
except Exception:  # pragma: no cover - optional dependency fallback
    spacy = None
    Language = Any  # type: ignore[assignment]
    Example = Any  # type: ignore[assignment]


class SecurityNerTrainingError(RuntimeError):
    """Raised when the optional spaCy training stack is unavailable."""


def load_security_annotations(data_path: str | None = None) -> list[dict[str, Any]]:
    """Load JSONL annotations for the custom security NER model."""
    config = load_yaml_config("config/extraction.yaml")
    default_path = config.get("spacy", {}).get("training_data_path", "tests/fixtures/security_ner_annotations.jsonl")
    resolved = ROOT_DIR / (data_path or default_path)
    annotations: list[dict[str, Any]] = []
    with resolved.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            annotations.append(json.loads(line))
    return annotations


def train_custom_security_ner(
    output_dir: str | None = None,
    data_path: str | None = None,
    base_model: str = "en_core_web_sm",
    iterations: int = 10,
    dropout: float = 0.2,
) -> Path:
    """Train and persist a custom spaCy NER model for PRODUCT, VERSION, and SEVERITY entities."""
    if spacy is None:
        raise SecurityNerTrainingError("spaCy is not installed. Install requirements-ml.txt to train the custom NER model.")

    config = load_yaml_config("config/extraction.yaml")
    default_output_dir = config.get("spacy", {}).get("default_output_dir", "artifacts/security_spacy_model")
    target_dir = ROOT_DIR / (output_dir or default_output_dir)

    annotations = load_security_annotations(data_path=data_path)
    try:
        nlp = spacy.load(base_model)
    except Exception:
        nlp = spacy.blank("en")

    ner = nlp.get_pipe("ner") if "ner" in nlp.pipe_names else nlp.add_pipe("ner")
    for example in annotations:
        for entity in example.get("entities", []):
            ner.add_label(str(entity["label"]))

    training_examples = _build_examples(nlp, annotations)
    other_pipes = [pipe for pipe in nlp.pipe_names if pipe != "ner"]
    with nlp.disable_pipes(*other_pipes):
        optimizer = nlp.initialize(get_examples=lambda: training_examples)
        for _ in range(iterations):
            nlp.update(training_examples, sgd=optimizer, drop=dropout)

    target_dir.mkdir(parents=True, exist_ok=True)
    nlp.to_disk(target_dir)
    return target_dir


def _build_examples(nlp: Language, annotations: list[dict[str, Any]]) -> list[Example]:
    examples: list[Example] = []
    for sample in annotations:
        entities = [
            (int(entity["start"]), int(entity["end"]), str(entity["label"]))
            for entity in sample.get("entities", [])
        ]
        examples.append(Example.from_dict(nlp.make_doc(str(sample["text"])), {"entities": entities}))
    return examples
