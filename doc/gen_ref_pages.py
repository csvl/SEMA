
# https://mkdocstrings.github.io/recipes/#automatic-code-reference-pages

"""Generate the code reference pages and navigation."""
from pathlib import Path
import mkdocs_gen_files

nav = mkdocs_gen_files.Nav()

# Adjust root to be the top-level directory of the project
root = Path(__file__).resolve().parent.parent
srcs = [
    root / "sema_toolchain"]

for src in srcs:
    for path in sorted(src.rglob("*.py")):
        if "/script/" not in path.as_posix() and \
            "/scripts/" not in path.as_posix() and \
            "setup.py" not in path.as_posix() and \
            "/submodules/" not in path.as_posix() and \
            "/penv-fix" not in path.as_posix():
            module_path = path.relative_to(root).with_suffix("").as_posix().replace("/", ".")
            doc_path = path.relative_to(root).with_suffix(".md")
            full_doc_path = Path("reference", doc_path)

            parts = tuple(module_path.split("."))

            if parts[-1] == "__init__":
                parts = parts[:-1]
                doc_path = doc_path.with_name("index.md")
                full_doc_path = full_doc_path.with_name("index.md")
            elif parts[-1] == "__main__":
                continue

            nav[parts] = doc_path.as_posix()

            with mkdocs_gen_files.open(full_doc_path, "w") as fd:
                ident = ".".join(parts)
                fd.write(f"::: {ident}")

            # mkdocs_gen_files.set_edit_path(full_doc_path, path.relative_to(root))
            mkdocs_gen_files.set_edit_path(full_doc_path, Path("../") / path)  


with mkdocs_gen_files.open("reference/SUMMARY.md", "w") as nav_file:
    nav_file.writelines(nav.build_literate_nav())
