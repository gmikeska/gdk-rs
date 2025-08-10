#!/usr/bin/env python3
import sys
import re

def extract_test_module(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Find the test module
    pattern = r'#\[cfg\(test\)\]\s*mod\s+tests\s*\{(.*?)(?=\n\}$|\n\}\s*$|\n\}\s*\n)'
    match = re.search(pattern, content, re.DOTALL | re.MULTILINE)
    
    if match:
        # Extract just the content inside the module
        test_content = match.group(1).strip()
        
        # Calculate the line range
        start_pos = match.start()
        lines_before = content[:start_pos].count('\n')
        test_module_start = lines_before + 1
        
        # Find the closing brace
        module_text = match.group(0)
        module_lines = module_text.count('\n')
        test_module_end = test_module_start + module_lines + 1
        
        return test_content, test_module_start, test_module_end
    
    return None, None, None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: extract_test_module.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    test_content, start_line, end_line = extract_test_module(file_path)
    
    if test_content:
        print(f"=== TEST MODULE FOUND: lines {start_line}-{end_line} ===")
        print(test_content)
        print(f"=== END TEST MODULE ===")
        print(f"START_LINE:{start_line}")
        print(f"END_LINE:{end_line}")
    else:
        print("No test module found")
