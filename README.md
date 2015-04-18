3dmmInternals
=============

Reverse engineering 3D Movie Maker. So far this contains:

* functions.json, a listing of all functions in 3dmovie.exe, generated from several sources
* classes.json, a listing of detected classes.
* classes.txt, a plain text file of some class info, needs to be merged into classes.json
* globals.json, a listing of manually determined globals


TODO
=============
* Generate globals.json data from automatic globals-finding script as well
* clean up classes.txt research and make it into a structured .json file
* build an HTML/JS interface to functions.json/globals.json


Copyright
============
* All python code is copyright Foone Turing, and is BSD licensed. 
* 3D Movie Maker is copyright Microsoft
* All of generate/include/ is from the BRender SDK, and is copyright Argonaut Software aka Argonaut Games.  