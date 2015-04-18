@echo off
python find_constructors.py
python parse_exe.py 
python find_classes.py
python process_headers.py
python build_func_list.py