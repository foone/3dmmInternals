import json

with open('class_tree.json','rb') as f:
	classes=json.load(f)

def walkTree(class_name, parent, depth):
	klass=classes[class_name]
	if parent == klass['parent']:
		touched.add(class_name)
		print '{}* {}'.format('  '*depth, class_name.replace(' ','_'))
		walk(class_name, depth+1)

def walk(parent=None, depth=0):
	for class_name in sorted(classes.keys()):
		walkTree(class_name, parent, depth)
touched=set()
walk()
untouched=set(classes.keys())-touched
if untouched:
	print 'UNTOUCHED!',untouched
