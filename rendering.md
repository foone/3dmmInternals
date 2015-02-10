Rendering
=========


classBWLD::render (@00474590) is the main method for rendering. 

if the dirty flag at +16C is set to 0, all rendering is skipped.

Pre-render handlers
-------------------

+170 is checked and the following code is skipped if it's 0

1. +30 is checked and if non-zero, ptr is set to *(+30)
2. if the byte at ptr+12 is 0, we skip the next step
3. the function pointer at ESI+170 is called with ptr as an argument
4. ptr is set to *ptr
5. if ptr is not zero, we loop to #2


Render background
-----------------
classBWLD::renderBackground(@00474740) is called to render 
the background MBMP to the framebuffer and the ZBMP to the zbuffer

*TODO: more details*

Region?
-------
	classREGN::00426BC0 is called with arguments (+15C, 0) and *this* set to +160
	classREGN::004262A0 is called with arguments (0) and *this* set to +15C

BRender
-------

BrZbSceneRender@0048854F is called with arguments:

* world (br_actor*) classBWLD::+28
* camera (br_actor*) classBWLD::+84
* colour_buffer (br_pixelmap*) classBWLD::+10C
* depth_buffer (br_pixelmap*) classBWLD::+138


Post-render handlers
-------------------
1. ptr is set to *(+30)
2. if the byte at ptr+12 is 0 we skip to the next iteration
3. if +178 is 0, we skip calling anything this iteration
4. *this* is set to a local variable +0C
5. classBWLD::+178 is called with arguments (ptr,*this*)
6. @00426CE0 is called with arguments:
	* *this*
	* 0 (*doublecheck this: it's ebx but it doesn't seem to be set*)
7. ptr is set to *ptr
8. if ptr is not zero, we loop to #2

Region? again
-------
	classREGN::00426BC0 is called with arguments (+15C, 0) and *this* set to +160


Final
-----
dirty (+16C) is set to 0. Until it is reset to a non-zero value, any attempts to render will be skipped.