"""Derive a NixOS-specific SCA policy from a stock Wazuh policy.

Copies the source policy and, for each check id given on the command line,
neutralises it so Wazuh reports it as "Not applicable" instead of "Failed" —
without removing it. The policy therefore keeps the full original check count;
only the result of the listed checks changes.

Mechanism (per Wazuh SCA docs): a content-check rule whose target does not
exist evaluates to "Not applicable", and under `condition: all`, if any rule is
Not applicable and none Failed, the whole check is Not applicable. So each
targeted check has its rules replaced with a single content check against a
file that never exists, and its condition forced to `all`. Everything else in
the block (id, title, compliance, rationale, remediation) is left untouched.

The source is located by its policy id rather than by filename, so an agent
upgrade that renames the file does not silently turn this into a no-op.

Text is edited line-wise instead of being round-tripped through a YAML parser:
the checks carry regexes full of quoting-sensitive characters, and a reserialise
would rewrite every one of them. This way anything not explicitly changed stays
byte-for-byte identical to what upstream shipped.

Usage: filter.py SRC_DIR OUT_FILE SRC_ID NEW_ID NEW_NAME EXPECTED_SRC_NAME ID [ID ...]
"""

import pathlib
import re
import sys

CHECK_RE = re.compile(r"^(\s*)-\s+id:\s*(\d+)\b")

# A content check against a path that will never exist. Absent target => the
# rule is "Not applicable" rather than Failed.
NA_MARKER_PATH = "/etc/.wazuh-sca-nixos-not-applicable"
NA_RULE = f"f:{NA_MARKER_PATH} -> r:^applicable$"


def find_source(src_dir, policy_id):
    """Return the policy file in src_dir whose header declares policy_id."""
    id_re = re.compile(r'^\s*id:\s*["\']?' + re.escape(policy_id) + r'["\']?\s*$')
    candidates = sorted(src_dir.glob("*.yml")) + sorted(src_dir.glob("*.yaml"))
    for path in candidates:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        head = text.split("\nchecks:", 1)[0]
        if any(id_re.match(line) for line in head.split("\n")):
            return path
    sys.exit(
        f"error: no policy with id '{policy_id}' in {src_dir}\n"
        f"       looked at: {', '.join(p.name for p in candidates) or '(no yml files)'}"
    )


def _indent(s):
    return len(s) - len(s.lstrip())


def mark_not_applicable(lines, na_ids):
    """Rewrite each listed check block so it evaluates to Not applicable.

    Within a targeted `- id: N` block: force `condition: all` and replace the
    entire `rules:` list with the single NA rule. All other lines are kept.
    """
    out, marked, i = [], set(), 0
    while i < len(lines):
        m = CHECK_RE.match(lines[i])
        if not (m and int(m.group(2)) in na_ids):
            out.append(lines[i])
            i += 1
            continue

        block_indent = len(m.group(1))  # indent of "- id:"
        key_indent = block_indent + 2  # keys inside the block ("  " past "- ")
        marked.add(int(m.group(2)))
        out.append(lines[i])  # the id line itself
        i += 1

        while i < len(lines):
            line = lines[i]
            nxt = CHECK_RE.match(line)
            if nxt and len(nxt.group(1)) == block_indent:
                break  # next check at same depth
            if line and not line[0].isspace():
                break  # next top-level key (end of checks list)

            cond = re.match(r"^(\s*)condition:\s*", line)
            rules = re.match(r"^(\s*)rules:\s*$", line)

            if cond and _indent(line) == key_indent:
                out.append(f"{cond.group(1)}condition: all")
                i += 1
                continue

            if rules and _indent(line) == key_indent:
                ind = rules.group(1)
                out.append(f"{ind}rules:")
                out.append(f"{ind}  - '{NA_RULE}'")
                i += 1
                # Drop the original rule list items (indented past the key).
                while i < len(lines):
                    l2 = lines[i]
                    if l2.strip() == "" or _indent(l2) <= key_indent:
                        break
                    i += 1
                continue

            out.append(line)
            i += 1

    return out, marked


def rewrite_header(lines, new_id, new_file, new_name):
    """Rewrite id/file/name in the policy: block only (the first one wins)."""
    out, in_policy, done = [], False, set()
    for line in lines:
        if re.match(r"^policy:\s*$", line):
            in_policy = True
            out.append(line)
            continue
        if in_policy:
            if line and not line[0].isspace():  # left the policy: block
                in_policy = False
            else:
                for key, val in (("id", new_id), ("file", new_file), ("name", new_name)):
                    if key in done:
                        continue
                    m = re.match(r"^(\s*)" + key + r':\s*["\']?(.*?)["\']?\s*$', line)
                    if m:
                        line = f'{m.group(1)}{key}: "{val}"'
                        done.add(key)
                        break
        out.append(line)
    missing = {"id", "file", "name"} - done
    if missing:
        sys.exit(f"error: policy: header has no {', '.join(sorted(missing))} field(s)")
    return out


def main():
    src_dir, out_file, src_id, new_id, new_name, expected_src_name = (
        pathlib.Path(sys.argv[1]),
        pathlib.Path(sys.argv[2]),
        sys.argv[3],
        sys.argv[4],
        sys.argv[5],
        sys.argv[6],
    )
    na_ids = {int(a) for a in sys.argv[7:]}

    src = find_source(src_dir, src_id)

    if src.name != expected_src_name:
        print(
            f"sca-policy: WARNING: source is '{src.name}', but ossec.conf disables "
            f"'{expected_src_name}'. Both policies will run and the stock (Failed) "
            f"results will still be reported. Fix with:\n"
            f"sca-policy:   services.wazuh-agent.scaSourceFile = \"{src.name}\";",
            file=sys.stderr,
        )

    lines = src.read_text(errors="replace").split("\n")
    lines, marked = mark_not_applicable(lines, na_ids)
    lines = rewrite_header(lines, new_id, out_file.name, new_name)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(lines))

    print(
        f"sca-policy: {src.name} -> {out_file} "
        f"({len(marked)}/{len(na_ids)} checks marked not-applicable, full check count kept)"
    )
    absent = na_ids - marked
    if absent:
        print(f"sca-policy: warning: not found in source: {sorted(absent)}")


if __name__ == "__main__":
    main()
