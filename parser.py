from __future__ import print_function
import sys

sys.path.extend(['.', '..'])

from pycparser import parse_file, c_generator, c_parser, c_ast
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

snprintf_text = r"""
int snprintf_n_read = snprintf(_param_str, _nbytes, _format, _vars);
"""

get_register_template_text = r"""
unsigned int _name = get_uint32_t_register_by_name(target->reg_cache, _reg);
"""

void_params_text = r"""
char* to_delete(int depth){
	char *param_str = malloc(5);
	int snprintf_n_read = snprintf(param_str, 5, "void");
	return param_str;
}
"""

# TODO: erase dump_param and len if param is literal
single_param_text = r"""
char* to_delete(int depth){
	char *param_str;
	int len;

	unsigned int addr = get_uint32_t_register_by_name(target->reg_cache, "r0");
	len = dump_param(depth, addr, &param_str);

	return param_str;
}
"""

#TODO: erase dump_param if param is literal
multiple_param_text = r"""
char* to_delete(int depth){
	char *param_str, **dumped_params;
	int len;

	dumped_params = malloc(_nr_params*sizeof(char*));

	len = dump_pollfd(depth, &dumped_params[0]);
	len += dump_uint(&dumped_params[1]);
	len += dump_long(&dumped_params[2]);

	param_str = copy_params(dumped_params, _nr_params, len);

	free_dumped_params(dumped_params, _nr_params);

	return param_str;
}
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

'''
we should do:
	1) insert all the structs, typedefs and syscalls on the same file
	2) remove __user from params
	3) substitute ; by {}
	4) substitute "long" by "char*" (on each syscall retval type)

basic types of syscalls.h:
	long
	unsigned long
	int
	unsigned int
	unsigned
	char *

others:
	short
	https://en.wikipedia.org/wiki/C_data_types#Basic_types
'''

basic_types = {'long': "%d", 'int': "%d", 'unsigned long': "%u", 'unsigned int': "%u", 'unsigned': "%u"}

class FuncDefVisitor(c_ast.NodeVisitor):
	def visit_FuncDef(self, node):
		if "sys_" in node.decl.name:
			# Create function Body if it has no elements
			if node.body.block_items == None:
				node.body.block_items = []

			# Change method name
			node.decl.name = "dump_" + node.decl.name
			node.decl.type.type.type.declname = "dump_" + node.decl.type.type.type.declname

			params = node.decl.type.args.params

			if no_params(params[0]):
				void_params = parser.parse(void_params_text, filename='<nome>').ext[0]
				for block_item in void_params.body.block_items:
					node.body.block_items.append(block_item)
				node.decl.type.args.params = void_params.decl.type.args.params
				return

			if len(params) == 1:
				single_param = parser.parse(single_param_text, filename='<nome>').ext[0]
				snprintf_template = parser.parse(snprintf_text, filename='<nome>').ext[0]
				if isBasicType(params[0]):
					block_items = single_param.body.block_items
					del block_items[3] #dump_param
					del block_items[1] #int len
					snprintf_template.init.args.exprs[0].name = "param_str"
					snprintf_template.init.args.exprs[1].name = "22" #allocate 22(20 digits at most +"\0"+"-")
					snprintf_template.init.args.exprs[2].name = '"%s"' % basic_types[" ".join(params[0].type.type.names)] #use a dictionary???
					snprintf_template.init.args.exprs[3].name = "addr"
					block_items.insert(2, snprintf_template) # insert snprintf before return
				else: #TODO: inspect var to create "recursive" dump
					print("TODO")
				for block_item in single_param.body.block_items:
					node.body.block_items.append(block_item)
				node.decl.type.args.params = single_param.decl.type.args.params
				return

			i = 0
			for param in params:
				isBasicType(param)

				get_register = generate_get_register(param, i)
				#get_register_template
				node.body.block_items.append(get_register)
				i += 1

			node.decl.type.args.params = []

def no_params(param):
	if type(param.type.type) == c_ast.IdentifierType:
		return param.type.type.names[0] == "void"

def printParamInfo(param):
	print("param: %s" % type(param))
	print("param.name: %s" % param.name)
	print("param.type: %s" % type(param.type))
	if(type(param.type) == c_ast.TypeDecl):
		print("\tdeclname: %s" % param.type.declname)
		print("\tquals: %s" % param.type.quals)
		print("\ttype: %s" % type(param.type.type))
		print("\t\ttype.names: %s" % type(param.type.type.names))
		print("\t\ttype.names: %s" % param.type.type.names)
		print("\t\ttype.names: %s" % " ".join(param.type.type.names))
		print("\tcoord: %s" % param.type.coord)
		print("\t__weakref__: %s" % param.type.__weakref__)
	print()

def isBasicType(param):
	# param is not a ptr
	if type(param.type) == c_ast.TypeDecl:
		paramType = " ".join(param.type.type.names)
		print(paramType)
		if paramType in basic_types:
			return True
	return False
'''
	if isPtr(param) == False:
		paramType = " ".join(param.type.type.names)
		print(paramType)
		print()
'''

def isPtr(param):
	return type(param.type) == c_ast.PtrDecl

def isStruct(param):
	# assumption: structs are always single pointers or double pointers
	if isPtr(param): #*struct
		if isPtr(param.type): # **struct
			#print("returning **: %s " % (type(param.type.type.type.type) == c_ast.Struct) )
			return type(param.type.type.type.type) == c_ast.Struct
		#print("returning *: %s " % (type(param.type.type.type) == c_ast.Struct) )
		return type(param.type.type.type) == c_ast.Struct
	return False

def generate_get_register(param, i):
	get_register_template = parser.parse(get_register_template_text, filename='<nome>').ext[0]

	get_register_template.name 			= param.name
	get_register_template.type.declname = param.name
	get_register_template.init.args.exprs[1].name = '"r%d"' % i

	return get_register_template

def generate_malloc(param):
	malloc_template			= parser.parse(malloc_template_text, filename='<none>').ext[0]
	malloc_template.name	= param.name

	if isPtr(param.type) == False: # parameter is a single pointer
		declname = param.type.type.declname
	else: # parameter is a double pointer
		declname = param.type.type.type.declname

	malloc_template.type.type.declname		= declname
	malloc_template.init.args.exprs[0].name = "change_size_here"
	malloc_template.type.type				= param.type.type

	return malloc_template

class TypeDeclVisitor(c_ast.NodeVisitor):
	def visit_TypeDecl(self, node):
		print(type(node))
		print(node.declname)
		print(type(node.type))
		if type(node.type) == c_ast.IdentifierType:
			print("\t %s" % node.type)
		else:
			print("\t %s" % node.type.name)
			print("\t %s" % node.type.decls[0].name)
			print("\t %s" % node.type.decls[0].type)
			print("\t %s" % node.type.decls[0].init)
		print()

structs_template_text = r"""
typedef int		__kernel_pid_t;
typedef __kernel_pid_t          pid_t;
struct pollfd {
	int fd;
	short events;
	unsigned short revents;
	struct st two_digs;
	pid_t id;
	pid_t *pid;
	struct st *pid2;
};
struct st
{
	int a;
	int b;
};
typedef struct _st2
{
	int z;
	int y;
} st2;
typedef struct {
	int a;
}time_t;
"""

structs_template = parser.parse(structs_template_text, filename='<none>')

class DeclVisitor(c_ast.NodeVisitor):
	def __init__(self, struct_name):
		self.struct_name = struct_name
		self.var_types = []

	def get_var_types(self):
		return self.var_types

	def visit_Decl(self, node):
		if type(node.type) == c_ast.Struct:
			if node.type.name == self.struct_name:
				for var in node.type.decls:
					if type(var.type) == c_ast.TypeDecl:
						#print("\t %s" % var.name)
						#print("\t\t %s" % var.type.declname)
						if type(var.type.type) == c_ast.IdentifierType:
							#print("\t\t\t %s" % " ".join(var.type.type.names))
							print("%s %s" % (" ".join(var.type.type.names), var.name))
							self.var_types.append(" ".join(var.type.type.names))
						elif type(var.type.type) == c_ast.Struct:
							#print("\t\t\t %s" % var.type.type.name)
							print("%s %s" % (var.type.type.name, var.name))
							self.var_types.append(var.type.type.name)
					elif type(var.type) == c_ast.PtrDecl:
						if type(var.type.type) == c_ast.TypeDecl:
							if type(var.type.type.type) == c_ast.IdentifierType:
								#print("\t\t\t %s" % " ".join(var.type.type.type.names))
								print("%s *%s" % (" ".join(var.type.type.type.names), var.name))
							elif type(var.type.type.type) == c_ast.Struct:
								#print("\t\t\t %s" % var.type.type.type.name)
								print("%s *%s" % (var.type.type.type.name, var.name))
						elif type(var.type.type) == c_ast.PtrDecl: # double ptrs
							print("double ptr: %s" % type(var.type.type.type))
			#print(type(node))
			#print(node.name)
			#print(node.funcspec)
			#print(type(node.type))

'''
		else:
			print(node.type.declname)
			print(type(node.type.type))
			if type(node.type.type) == c_ast.IdentifierType:
				print("\t %s" % node.type.type)
			else:
				print("\t %s" % node.type.type.name)
				print("\t %s" % node.type.type.decls[0].name)
				print("\t %s" % node.type.type.decls[0].type)
				print("\t %s" % node.type.type.decls[0].init)
'''

v = DeclVisitor('pollfd')
v.visit(structs_template)
print(v.get_var_types())

#v = FuncDefVisitor()
#v.visit(syscalls)

#print("after:")
#print(generator.visit(syscalls))

