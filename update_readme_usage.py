import os

from src.Sema import Sema

sema = Sema(is_from_web=True)
with open("README_tmp.md", "r") as fh:
    long_description = fh.read()
    long_description = long_description.replace("$$SemaSCDG_usage$$", sema.args_parser.args_parser_scdg.parser.format_help())
    long_description = long_description.replace("$$SemaClassifier_usage$$", sema.args_parser.args_parser_class.parser.format_help())

with open("README.md", "w") as fh:
    fh.write(long_description)
    
    