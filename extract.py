import re
import os

log_file = "/home/kali/.gemini/antigravity/brain/a102061f-8975-43e0-83d9-7b896916cd87/.system_generated/logs/overview.txt"

def extract_file(filename):
    with open(log_file, "r") as f:
        content = f.read()
    
    # We look for "File Path: `file://...<filename>`"
    # followed by "Showing lines 1 to N"
    # Then we extract until "The above content"
    
    pattern = rf"File Path: `file://[^`]+{filename}`\nTotal Lines: \d+\nTotal Bytes: \d+\nShowing lines 1 to \d+\nThe following code has been modified.*?\n(.*?)(\nThe above content|\n```)"
    matches = list(re.finditer(pattern, content, re.DOTALL))
    
    if not matches:
        print(f"Could not find match for {filename}")
        return
        
    last_match = matches[-1].group(1)
    
    # Remove the line numbers
    cleaned = re.sub(r"^\d+:\s", "", last_match, flags=re.MULTILINE)
    cleaned = re.sub(r"^\d+:$", "", cleaned, flags=re.MULTILINE)
    
    out_path = f"/home/kali/.gemini/antigravity/scratch/noirnet/crates/{filename}"
    
    print(f"Found {filename}, length: {len(cleaned)}")
    
    with open(out_path, "w") as f:
        f.write(cleaned)

extract_file("noirnet-consensus/src/engine.rs")
extract_file("noirnet-network/src/p2p.rs")
extract_file("noirnet-vm/src/runtime.rs")
extract_file("noirnet-wallet/src/keys.rs")
