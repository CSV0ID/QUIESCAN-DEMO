import json
import os

from google import genai

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    return _client


_PROMPT = """You are a malware analyst. Analyze the following static features extracted from a file and produce:
1. A plain-English behavior summary (2-4 sentences, no jargon overload)
2. A risk score: one of: low | medium | high | critical

Scoring guide:
- low: benign-looking, no suspicious indicators
- medium: some suspicious strings or imports, could be legitimate
- high: multiple suspicious API calls, obfuscation, or known bad patterns
- critical: clear malware indicators — shellcode injection APIs, ransomware patterns, C2 URLs, etc.

If the file has high entropy (packed/encrypted), treat the packer itself as a suspicious indicator.

Respond ONLY with valid JSON:
{{"summary": "...", "risk_score": "low|medium|high|critical"}}

File features:
{features}"""


_RISKS = ("low", "medium", "high", "critical")


def _heuristic_risk(features: dict) -> str:
    """Fallback risk when the LLM is unavailable — based on static signals only."""
    packed = features.get("packed_likely")
    iocs = features.get("urls_ips")
    if packed and iocs:
        return "high"
    if packed or iocs:
        return "medium"
    return "low"


def analyze(features: dict) -> dict:
    """Never throws. On any LLM hiccup, degrade to a static-signal verdict so the
    scan still returns YARA/hash/entropy results instead of 500ing."""
    try:
        safe_features = {
            k: v
            for k, v in features.items()
            if k not in ("strings_sample",)  # trim noise, keep signals
        }
        safe_features["strings_sample"] = features.get("strings_sample", [])[:20]

        prompt = _PROMPT.format(features=json.dumps(safe_features, indent=2))

        from google.genai import errors as genai_errors
        primary_model = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")
        fallback_model = os.environ.get("GEMINI_FALLBACK_MODEL", "gemini-2.5-flash")
        try:
            response = _get_client().models.generate_content(
                model=primary_model,
                contents=prompt,
            )
        except genai_errors.ServerError:
            import logging
            logging.getLogger("quiescan").warning(
                "Primary model %s unavailable, trying fallback %s", primary_model, fallback_model
            )
            response = _get_client().models.generate_content(
                model=fallback_model,
                contents=prompt,
            )

        text = response.text
        if text is None:
            import logging
            logging.getLogger("quiescan").error(
                "LLM raw response had no text. Full response: %r", response
            )
            raise ValueError("Empty response text from Gemini")
        text = text.strip()
        # strip markdown code fences if model wraps output
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        data = json.loads(text.strip())
        if not isinstance(data, dict):
            import logging
            logging.getLogger("quiescan").error(
                "LLM parsed JSON was not a dict. Raw text: %r Parsed: %r", text, data
            )
            raise ValueError("Parsed JSON is not a dict")
        risk = data.get("risk_score", "")
        if risk not in _RISKS:
            risk = _heuristic_risk(features)
        return {
            "summary": (data.get("summary") or "").strip() or "Automated summary unavailable.",
            "risk_score": risk,
        }
    except Exception as e:
        import logging
        import traceback
        logging.getLogger("quiescan").error(
            "LLM analysis failed: %r\n%s", e, traceback.format_exc()
        )
        return {
            "summary": "AI summary unavailable — verdict based on static signals only.",
            "risk_score": _heuristic_risk(features),
        }
