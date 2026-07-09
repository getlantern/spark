import { describe, it, expect } from "vitest";
import { poToMap } from "./po-to-json.mjs";

const SAMPLE = `msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\\n"

msgid "settings"
msgstr "Settings"

msgid "greeting"
msgstr "Hello \\"world\\"\\nline2"

msgid "empty_one"
msgstr ""
`;

describe("poToMap", () => {
  it("extracts msgid->msgstr, drops header and empty translations", () => {
    const map = poToMap(SAMPLE);
    expect(map.settings).toBe("Settings");
    expect(map.greeting).toBe('Hello "world"\nline2');
    // vitest 4.1.10's `.toHaveProperty("")` throws on an empty-string path
    // (Cannot read properties of null (reading 'map')), so assert the same
    // intent — no empty-string key — via Object.keys instead.
    expect(Object.keys(map)).not.toContain("");
    expect(map).not.toHaveProperty("empty_one");
  });
});
