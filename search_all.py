import json
import glob
import re

files = glob.glob("/home/kali/.gemini/antigravity/brain/*/.system_generated/logs/overview.txt")

best_match = ""

for log_file in files:
    with open(log_file, "r") as f:
        lines = f.readlines()
        for line in lines:
            try:
                data = json.loads(line)
                if 'tool_calls' in data:
                    for tc in data['tool_calls']:
                        if tc['name'] == 'write_to_file':
                            target_file = tc['args'].get('TargetFile', '')
                            if 'engine.rs' in target_file:
                                content = tc['args'].get('CodeContent', '')
                                if len(content) > len(best_match):
                                    best_match = content
                        elif tc['name'] == 'replace_file_content':
                            target_file = tc['args'].get('TargetFile', '')
                            if 'engine.rs' in target_file:
                                # if it was a replace we might not have the full file, but let's check
                                content = tc['args'].get('ReplacementContent', '')
                                if len(content) > len(best_match):
                                    best_match = content
            except json.JSONDecodeError:
                pass

print(f"Found something? {len(best_match) > 0}")

if best_match:
    with open("crates/noirnet-consensus/src/engine.rs", "w") as f:
        f.write(best_match)
    print(f"Restored engine.rs from log (length {len(best_match)})")

