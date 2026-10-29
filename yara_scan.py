import os
import yara

_rules = None
_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules", "index.yar")


def _get_rules():
    global _rules
    if _rules is None:
        try:
            _rules = yara.compile(filepath=os.path.abspath(_RULES_PATH))
        except yara.SyntaxError:
            # ponytail: some rules in the index have broken syntax; compile safe subsets individually
            safe = {}
            for name, fname in [
                ("packers", "packers_index.yar"),
                ("antidebug", "antidebug_antivm_index.yar"),
                ("capabilities", "capabilities_index.yar"),
            ]:
                path = os.path.abspath(os.path.join(os.path.dirname(_RULES_PATH), fname))
                try:
                    yara.compile(filepath=path)
                    safe[name] = path
                except yara.SyntaxError:
                    pass
            _rules = yara.compile(filepaths=safe) if safe else None
    return _rules


def scan(path: str) -> list[dict]:
    try:
        rules = _get_rules()
        if rules is None:
            return []
        matches = rules.match(filepath=path)  # scans from disk, no RAM load
        return [
            {"rule": m.rule, "tags": m.tags, "namespace": m.namespace}
            for m in matches
        ]
    except Exception as e:
        return [{"error": str(e)}]
