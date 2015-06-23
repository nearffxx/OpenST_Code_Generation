from __future__ import print_function
import sys

sys.path.extend(['.', '..'])

from pycparser import c_generator, c_parser, c_ast
parser = c_parser.CParser()
generator = c_generator.CGenerator()

def read_file_as_string(filename):
	temp = open(filename, 'r')
	content = temp.read()
	temp.close()
	return content

structs_text = read_file_as_string("a.h");
syscalls_text = read_file_as_string("a.c");

malloc_template_text = r"""
struct _struct_name *_name = malloc(_size);
"""

get_register_template_text = r"""
unsigned int _name = get_uint32_t_register_by_name(target->reg_cache, _reg);
"""

'''
md_template_text = r"""
int *_name = get_address_value(target, _addr, _size);
"""
mdw = parser.parse(md_template_text, filename='<none>')
'''

#ast = parser.parse(text, filename='<none>')
syscalls = parser.parse(syscalls_text, filename='<none>')
structs = parser.parse(structs_text, filename='<nome>')

#print("before:")
#print(generator.visit(syscalls))

def isStruct(param):
	# assumption: structs are always single pointers or double pointers
	if type(param.type) == c_ast.PtrDecl: #*struct
		if type(param.type.type) == c_ast.PtrDecl: # **struct
			#print("returning **: %s " % (type(param.type.type.type.type) == c_ast.Struct) )
			return type(param.type.type.type.type) == c_ast.Struct
		#print("returning *: %s " % (type(param.type.type.type) == c_ast.Struct) )
		return type(param.type.type.type) == c_ast.Struct
	return False

def generate_malloc(param):
	malloc_template			= parser.parse(malloc_template_text, filename='<none>').ext[0]
	malloc_template.name	= param.name

	if type(param.type.type) != c_ast.PtrDecl: # parameter is a single pointer
		declname = param.type.type.declname
	else: # parameter is a double pointer
		declname = param.type.type.type.declname

	malloc_template.type.type.declname		= declname
	malloc_template.init.args.exprs[0].name = "change_size_here"
	malloc_template.type.type				= param.type.type

	return malloc_template

'''
we should do:
	1) insert all the structs, typedefs and syscalls on the same file
	2) remove __user from params
	3) substitute ; by {}

basic types:
	long
	unsigned long
	int
	unsigned int
	unsigned
	char *

'''

class FuncDefVisitor(c_ast.NodeVisitor):
	def visit_FuncDef(self, node):
		if "sys_" in node.decl.name:
			# Create function Body if it has no elements
			if(node.body.block_items == None):
				node.body.block_items = []
			# Change method name
			node.decl.name = "dump_" + node.decl.name
			node.decl.type.type.declname = "dump_" + node.decl.type.type.declname
			i = 0
			for param in node.decl.type.args.params:
				get_register_template = parser.parse(get_register_template_text, filename='<nome>').ext[0]

				get_register_template.name 			= param.name
				get_register_template.type.declname = param.name
				get_register_template.init.args.exprs[1].name = '"r%d"' % i
				#get_register_template
				node.body.block_items.append(get_register_template)
				i += 1

			node.decl.type.args.params = []

v = FuncDefVisitor()
v.visit(syscalls)

print("after:")
print(generator.visit(syscalls))

