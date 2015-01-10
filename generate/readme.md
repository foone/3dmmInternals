# What is this?
functions.json is a listing of all the functions in the main 3D Movie Maker executable (3DMOVIE.EXE), automatically generated from multiple sources and tools. 

# How to generate functions.json
1. Open 3DMOVIE.EXE with OllyDbg 2.x, select the entire contents (click first line, scroll to the bottom, shift-click the last line). Right click, edit, copy as table. 
2. Paste into a new text document named disassembly.txt. Save into this directory.
3. run find_constructors.py to generate constructors.txt.
4. Open 3DMOVIE.EXE in Ida Pro. Select all the functions in the function sub view, hit ctrl-insert to copy them. Paste into a new text file named "ida.txt".
5. Copy 3DMOVIE.EXE into this directory (not needed if 3DMM has been installed on the system)
6. Create a virtualenv, activate it, then install from requirements.txt:

```
virtualenv venv
venv\scripts\activate
pip install -r requirements.txt
```

7. run parse_exe.py to generate fpo.json
8. Install node.js, then install jsonlint globally.

```
npm install -g jsonlint
```

9. run build_func_list.py to build the final functions.json file. You're done!

# TODO/Gotchas

* Right now build_func_list.py will overwrite any manual changes. It shouldn't, it should merge them.
* jsonlint should be optional! if it's not installed, just generate an ugly json.
* TODO: My ollydbg has manual function naming, both BRender and misc. Should split this out!
* TODO: Merge in the extracted brender.lib/.h info. 
* TODO: Add vtable dumps to constructors, indicate which functions belong to which classes within those functions. 
