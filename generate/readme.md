# What is this? # 
functions.json is a listing of all the functions in the main 3D Movie Maker executable (3DMOVIE.EXE), automatically generated from multiple sources and tools. 

# How to generate functions.json # 
1. Open 3DMOVIE.EXE with OllyDbg 2.x, select the entire contents (click first line, scroll to the bottom, shift-click the last line). Right click, edit, copy as table. 
2. Paste into a new text document named disassembly.txt. Save into this directory.
3. run find_constructors.py to generate constructors.txt
4. Open 3DMOVIE.EXE in Ida Pro. Select all the functions in the function sub view, hit ctrl-insert to copy them. Paste into a new text file named "ida.txt".
5. Copy 3DMOVIE.EXE into this directory (not needed if 3DMM has been installed on the system)
6. Create a virtualenv, activate it, then "pip install -r requirements.txt".
7. run parse_exe.py to generate fpo.json
8. run build_func_list.py to build the final functions.json file. You're done!
