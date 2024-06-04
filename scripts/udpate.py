# add_code_to_module.py
# Script to add a code snippet to all Python files in a specified module directory recursively

import os
import fileinput
import shutil

def add_code_to_files(module_path, code_snippet):
    """Add a code snippet to all Python files in the specified module directory recursively."""
    if not os.path.exists(module_path):
        print(f"The module path {module_path} does not exist.")
        return
    
    for root, dirs, files in os.walk(module_path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                add_code_to_file(file_path, code_snippet)

def add_code_to_file(file_path, code_snippet):
    """Insert the code snippet at the beginning of the specified file."""
    # Create a backup of the original file
    backup_path = file_path + ".bak"
    shutil.copyfile(file_path, backup_path)
    print(f"Created a backup of {file_path} at {backup_path}")
    with fileinput.input(files=file_path, inplace=True) as file:
        for line in file:
            if file.isfirstline():
                print(code_snippet, end='')
            print(line, end='')

def main():
    """Main function to add code snippet to all Python files in a specified module."""
    module_path = "sema_toolchain/"
    code_snippet = "import os\nimport sys\n\nSCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))\nsys.path.append(os.path.dirname(SCRIPT_DIR))\n"

    print(f"Adding code snippet to all Python files in {module_path} recursively...")
    add_code_to_files(module_path, code_snippet)
    print("Code snippet added successfully.")

if __name__ == "__main__":
    main()
