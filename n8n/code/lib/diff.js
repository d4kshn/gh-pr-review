// Unified-diff helpers for GitHub "patch" strings (hunks only, no file headers).
const Diff = (() => {
  const HUNK = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

  // Returns added lines with their line numbers on the PR head side, plus hunk ranges.
  function parsePatch(patch) {
    const added = [];
    const hunks = [];
    let newLine = 0;
    let inHunk = false;
    for (const raw of String(patch || '').split('\n')) {
      const m = HUNK.exec(raw);
      if (m) {
        newLine = Number(m[3]);
        hunks.push({ start: newLine, end: newLine + (m[4] === undefined ? 1 : Number(m[4])) - 1 });
        inHunk = true;
        continue;
      }
      if (!inHunk) continue;
      if (raw.startsWith('+')) {
        added.push({ line: newLine, text: raw.slice(1) });
        newLine++;
      } else if (raw.startsWith('-') || raw.startsWith('\\')) {
        // removed line or "\ No newline at end of file": head numbering unchanged
      } else {
        newLine++;
      }
    }
    return { added, hunks, addedLines: added.map((a) => a.line) };
  }

  // True when any added line falls inside [start, end].
  function touchesAdded(addedLines, start, end) {
    const s = Number(start) || 0;
    const e = Number(end) || s;
    return (addedLines || []).some((l) => l >= s && l <= e);
  }

  const inHunks = (hunks, line) => (hunks || []).some((h) => line >= h.start && line <= h.end);

  return { parsePatch, touchesAdded, inHunks };
})();
