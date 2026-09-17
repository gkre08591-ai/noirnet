import re

log_file = "/home/kali/.gemini/antigravity/brain/a102061f-8975-43e0-83d9-7b896916cd87/.system_generated/logs/overview.txt"
with open(log_file, "r") as f:
    text = f.read()

# Look for all matches of engine.rs contents in view_file outputs
matches = re.findall(r'File Path: `[^`]+engine\.rs`\nTotal Lines: \d+\nTotal Bytes: \d+\nShowing lines 1 to \d+\nThe following code has been modified.*?\n(.*?)\nThe above content', text, re.DOTALL)

best_match = ""
for match in matches:
    if len(match) > len(best_match):
        best_match = match

if best_match:
    cleaned = re.sub(r'^\d+:\s', '', best_match, flags=re.MULTILINE)
    cleaned = re.sub(r'^\d+:$', '', cleaned, flags=re.MULTILINE)
    with open("crates/noirnet-consensus/src/engine.rs", "w") as f:
        f.write(cleaned)
    print(f"Restored engine.rs from log (length {len(cleaned)})")
else:
    print("Could not find full engine.rs in logs!")
