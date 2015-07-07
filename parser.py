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

structs_text	= read_file_as_string("a.h");
syscalls_text	= read_file_as_string("a.c");

malloc_template_text = r"""
struct _struct_name *_name = malloc(_size);
"""

md_template_text = r"""
unsigned int *value = get_address_value(target, _addr, _size);
__param_name = *value;
free(value);
"""

void_params_text = r"""
char* to_delete(int depth, struct target *target){
	char *param_str = malloc(5);
	int snprintf_n_read = snprintf(param_str, 5, "void");
	return param_str;
}
"""

snprintf_text = r"""
int snprintf_n_read = snprintf(_param_str, _nbytes, _format, _vars);
"""

get_register_template_text = r"""
unsigned int _name = get_uint32_t_register_by_name(target->reg_cache, _reg);
"""

dump_param_text = r"""
void to_delete() {
	len += dump_(depth, addr, &param_str[_index]);
}
"""

dump_from_reg_text = r"""
int dump_type_from_reg(unsigned int reg_value, char **param_str){
	int snprintf_n_read = snprintf(*param_str, __num_chars, __format, reg_value);
	return snprintf_n_read;
}
"""

get_address_value_template_text = r"""
unsigned int *value = get_address_value(target, __addr, __size);
"""

dump_from_mem_text = r"""
int dump_type_from_mem(unsigned int addr, char **param_str, unsigned int size, struct target* target){
	unsigned int *value = get_address_value(target, addr, size);
	int snprintf_n_read = snprintf(*param_str, __num_chars, __format, *value);
	free(value);
	return snprintf_n_read;
}
"""

dump_sys_text = r"""
char* to_delete(int depth, struct target *target){
	char **dumped_params;
	char *param_str;
	int len = 0;

	dumped_params = malloc(_nr_params*sizeof(char*));

	len += 1+_nr_params-1+2;
	param_str = copy_params(dumped_params, _nr_params, len);

	free_dumped_params(dumped_params, _nr_params);

	return param_str;
}
"""

#TODO: does not need to be necessarily a pointer when depth==0, may be a struct (test on OpenOCD)
dump_complex_type_template = r"""
int _funcname(int depth, unsigned int addr, char **dumped_params, struct target *target) {
	char **dumped_type_params;
	int len = 0;

	if(depth < 0)
	{
		*dumped_params = malloc(0);
	} else if (depth == 0) {
		len = 11;
		*dumped_params = malloc(len);
		snprintf(*dumped_params, len, "0x%u", addr);
	} else {
		dumped_type_params = malloc(_nr_params*sizeof(char*));



		*dumped_params = copy_params(dumped_type_params, _nr_params, len);

		free_dumped_params(dumped_type_params, _nr_params);
	}

	return len;
}
"""

'''
mdw = parser.parse(md_template_text, filename='<none>')
'''

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

class FuncDefVisitor(c_ast.NodeVisitor):
	def __init__(self):
		self.created_func_names = []

	def no_params(self, param):
		if type(param.type.type) == c_ast.IdentifierType:
			return param.type.type.names[0] == "void"

	def generate_dump_param_call(self, paramType, paramName="addr", 
								hasDepth=-1, singleParam=False, from_where="",
								index=-1, dumped_name="", size=-1, hasTarget=False):
		dump_param_template = parser.parse(dump_param_text, filename='<nome>').ext[0].body.block_items[0]

		paramType += from_where

		dump_param_template.rvalue.name.name += paramType
		dump_param_template.rvalue.args.exprs[1].name = paramName
		if singleParam:
			dump_param_template.rvalue.args.exprs[2].expr = c_ast.ID('param_str')

		if index != -1:
			dump_param_template.rvalue.args.exprs[2].expr.name.name			= dumped_name
			dump_param_template.rvalue.args.exprs[2].expr.subscript.name	= str(index)

		if size != -1:
			dump_param_template.rvalue.args.exprs.append(c_ast.ID(str(size)))

		if hasTarget:
			dump_param_template.rvalue.args.exprs.append(c_ast.ID('target'))

		if hasDepth == -1:
			del dump_param_template.rvalue.args.exprs[0]
		elif 0 < hasDepth:
			dump_param_template.rvalue.args.exprs[0] = c_ast.ID('depth-'+str(hasDepth))

		return dump_param_template

	def generate_get_register(self, param, i):
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

	def getParamType(self, param, sep="_"):
		paramType = ""

		while isPtr(param):
			param = param.type

		if type(param.type) == c_ast.TypeDecl:
			paramType = get_type_from_typedecl(param.type, sep)
		else:
			print("[getParamType] SHOULD NOT HAPPEN")

		return paramType

	def visit_FuncDef(self, node):
		if "sys_" in node.decl.name:
			# Create function Body if it has no elements
			if node.body.block_items == None:
				node.body.block_items = []

			# Change method name
			node.decl.name = "dump_" + node.decl.name
			node.decl.type.type.type.declname = "dump_" + node.decl.type.type.type.declname

			params = node.decl.type.args.params

			# no params
			if self.no_params(params[0]):
				void_params = parser.parse(void_params_text, filename='<nome>').ext[0]
				for block_item in void_params.body.block_items:
					node.body.block_items.append(block_item)
				# Change params
				node.decl.type.args.params = void_params.decl.type.args.params
				return

			print()

			# single param
			if len(params) == 1:
				dump_sys		= parser.parse(dump_sys_text, filename='<nome>').ext[0]
				paramType		= self.getParamType(params[0])
				block_items		= dump_sys.body.block_items
				get_register	= self.generate_get_register(params[0], 0)

				del block_items[6] # free_dumped_params
				del block_items[5] # copy_params
				del block_items[4] # len += 1+_nr_params-1+2; (\0, commas, commas(_nr_params-1), parenthesis)
				del block_items[3] # malloc
				del block_items[2] # int len = 0
				del block_items[0] # dumped_params

				if isBasicType(params[0]):
					block_items.insert(1, get_register)

					dump_param_template = self.generate_dump_param_call(paramType, get_register.name,
																		singleParam=True, 
																		from_where="_from_reg")
					block_items.insert(2, dump_param_template) # insert dump_param_template call before return
					block_items[2] = block_items[2].rvalue

					function_name = dump_param_template.rvalue.name.name
					if function_name not in self.created_func_names:
						self.created_func_names.append(function_name)

						dump_from_reg = parser.parse(dump_from_reg_text, filename='<nome>').ext[0]
						dump_from_reg.decl.name 				= function_name
						dump_from_reg.decl.type.type.declname	= function_name

						# num chars
						dump_from_reg.body.block_items[0].init.args.exprs[1].name = basic_types[paramType][1]
						# format
						dump_from_reg.body.block_items[0].init.args.exprs[2].name = '"%s"' % basic_types[paramType][0]

						syscalls.ext.append(dump_from_reg)
				#inspect var to create "recursive" dump
				elif isPtr(params[0]):
					num_param_derefs = 0
					aux = params[0]
					while isPtr(aux):
						aux = aux.type
						num_param_derefs += 1
					print("IS/ARE PTR/PTRs: %d" % num_param_derefs)

					block_items_complex_type = parser.parse(dump_complex_type_template, filename='<none>').ext[0].body.block_items

					block_items_complex_type[2].iftrue.block_items[0].lvalue.expr.name = "param_str"
					# add return
					block_items_complex_type[2].iftrue.block_items.insert(1, block_items[1])

					iffalse_block_items = block_items_complex_type[2].iffalse.iftrue.block_items[:]
					iffalse_block_items[1].lvalue.expr.name = "param_str"
					iffalse_block_items[2].args.exprs[0].expr.name = "param_str"
					iffalse_block_items.append(block_items[1])
					block_items_complex_type[2].iffalse = None

					block_items.insert(1, block_items_complex_type[2])
					block_items.insert(1, block_items_complex_type[1])

					block_items.insert(3, get_register)
					#assignment = c_ast.Assignment('=', c_ast.ID('len'), c_ast.ID(str(basic_types["ptr"][1])))
					#block_items.insert(4, assignment)

					# TODO: prepare for more than one pointer
					j = 0
					while j < num_param_derefs:
						if j != 0: # more than 1 pointer
							md_template = parser.parse(md_template_text, filename='<none>').ext[0]
							print("HAHAH %s" % md_template.name) # name of var
							print("HAHAH %s" % md_template.type) # type of var
							print("HAHAH %s" % md_template.init) # get_address_value funccall
# md_template_text = r"""
# unsigned int *value = get_address_value(target, _addr, _size);
# __param_name = *value;
# free(value);
# """
						if_template = c_ast.If(
												c_ast.BinaryOp('==', c_ast.ID('depth'), c_ast.Constant('int', str(j))),
												c_ast.Compound(iffalse_block_items),
												None
											  )
						block_items.insert(4, if_template)
						j += 1
					if paramType not in basic_types:
						dump_param_template = self.generate_dump_param_call(paramType, get_register.name,
																			singleParam=True, hasTarget=True,
																			hasDepth=0)
						dump_param_template = dump_param_template.rvalue
						block_items.insert(-1, dump_param_template)

						dump_complex_type = parser.parse(dump_complex_type_template, filename='<none>').ext[0]

						dump_complex_type.decl.name 				= "dump_" + paramType
						dump_complex_type.decl.type.type.declname	= "dump_" + paramType

						if isPtrStruct(params[0]):
							#print("STRUCT: %s" % paramType)
							v = DeclVisitor(paramType)
						else:
							#print("TYPEDEF: %s" % paramType)
							v = DeclTypedef(paramType)

						#block_items_param_deref = dump_complex_type.body.block_items[2].iffalse.block_items

						v.visit(structs)
						types = v.get_var_types()

						print("TYPES hehe: %s" % types)
						types_depths = []
						max_typ_deref = 0
						for typ in types:
							num_typ_derefs = 0
							while typ[0] == '*':
								num_typ_derefs += 1
								typ = typ[1:]
							if max_typ_deref < num_typ_derefs:
								max_typ_deref = num_typ_derefs
							types_depths.append([typ, num_typ_derefs])
						print("TYPES DEPTHS hehe: %s" % types_depths)

						block_items_dump = dump_complex_type.body.block_items[2].iffalse.iffalse.block_items
						block_items_dump[0].rvalue.args.exprs[0].left.name	= str(len(types))
						block_items_dump[1].rvalue.args.exprs[1].name		= str(len(types))
						block_items_dump[2].args.exprs[1].name				= str(len(types))

						block_items_dump_cp = block_items_dump[:]
						dump_complex_type.body.block_items[2].iffalse.iftrue.block_items = block_items_dump_cp[:]

						i				= 0
						offset			= 0
						dump_iffalse	= dump_complex_type.body.block_items[2].iffalse
						while i < max_typ_deref:
							# TODO add if condition
							if_template = c_ast.If(
													c_ast.BinaryOp('==', c_ast.ID('depth'), c_ast.Constant('int', str(i))),
													c_ast.Compound(block_items_dump_cp),
													dump_iffalse.iffalse
												  )
							j = 0
							for typ_depth in types_depths:
								# len += dump_
								if typ_depth[1] == 0:
									dump_param_template = self.generate_dump_param_call(typ_depth[0], str(j),
																						singleParam=True, 
																						from_where="_from_mem")
									if_template.iftrue.block_items.insert(1+j, dump_param_template) # insert dump_param_template call before return

									# function_name = dump_param_template.rvalue.name.name
									# if function_name not in self.created_func_names:
									# 	self.created_func_names.append(function_name)

									# 	dump_from_reg = parser.parse(dump_from_reg_text, filename='<nome>').ext[0]
									# 	dump_from_reg.decl.name 				= function_name
									# 	dump_from_reg.decl.type.type.declname	= function_name

									# 	# num chars
									# 	dump_from_reg.body.block_items[0].init.args.exprs[1].name = basic_types[paramType][1]
									# 	# format
									# 	dump_from_reg.body.block_items[0].init.args.exprs[2].name = '"%s"' % basic_types[paramType][0]

									# 	syscalls.ext.append(dump_from_reg)
								elif( 0 < typ_depth[1] and i < typ_depth[1] ):
									# add dump_address_from_mem if unexistent
									dump_param_template = self.generate_dump_param_call("Ptr", str(j),
																						singleParam=True, 
																						from_where="_from_mem")
									if_template.iftrue.block_items.insert(1+j, dump_param_template) # insert dump_param_template call before return
								elif( 0 < typ_depth[1] and i >= typ_depth[1] ):
									for k in xrange(typ_depth[1]):
										print("a")
								else:
									print("THIS SHOULD NOT HAPPEN: new case")
								j += 1

							dump_iffalse.iffalse = if_template
							dump_iffalse = dump_iffalse.iffalse
							i += 1

						print(dump_iffalse.iffalse.block_items[0])
						j = 0
						for typ_depth in types_depths:
							if typ_depth[1] == 0:
								dump_param_template = self.generate_dump_param_call(typ_depth[0], str(j),
																					singleParam=True, 
																					from_where="_from_mem")
								dump_iffalse.iffalse.block_items.insert(1+j, dump_param_template) # insert dump_param_template call before return
							elif 0 < typ_depth[1]:
								for k in xrange(typ_depth[1]):
									get_address_value_template = parser.parse(get_address_value_template_text, filename='<none>').ext[0]
									get_address_value_template
									dump_iffalse.iffalse.block_items.insert(1+j+k, get_address_value_template)
									j += 1
									dump_param_template = self.generate_dump_param_call(typ_depth[0].replace('STRUCT',''), str(j),
																						singleParam=True, 
																						from_where="")
									dump_iffalse.iffalse.block_items.insert(1+j+k, dump_param_template)
							j += 1
						# # get max deref
						# for typ_depth in types_depths:
						# 	j = 0
						# 	dump_iffalse = dump_complex_type.body.block_items[2].iffalse
						# 	while typ[0] == "*":
						# 		if act_max_deref < j:
						# 			act_max_deref = j
						# 			if_template = c_ast.If(
						# 									c_ast.BinaryOp('==', c_ast.ID('depth'), c_ast.Constant('int', str(act_max_deref))),
						# 									c_ast.Compound(block_items_dump_cp),
						# 									dump_iffalse.iffalse
						# 								  )
						# 			dump_iffalse.iffalse = if_template
						# 			dump_iffalse = dump_iffalse.iffalse
						# 		j += 1
						# 		typ = typ[1:]
						# 	print("j-1: %s" % (j-1))

						syscalls.ext.append(dump_complex_type)
					else:
						dump_from_mem = parser.parse(dump_from_mem_text, filename='<none>').ext[0]
						dump_param_template = self.generate_dump_param_call(paramType, get_register.name,
																			singleParam=True, hasTarget=True,
																			from_where="_from_mem",
																			size=str(basic_types[paramType][2]))
						function_name = dump_param_template.rvalue.name.name
						dump_param_template = dump_param_template.rvalue
						block_items.insert(-1, dump_param_template)

						# add function if unexistent
						if function_name not in self.created_func_names:
							self.created_func_names.append(function_name)

							dump_from_mem = parser.parse(dump_from_mem_text, filename='<nome>').ext[0]
							dump_from_mem.decl.name 				= function_name
							dump_from_mem.decl.type.type.declname	= function_name

							# num chars
							dump_from_mem.body.block_items[1].init.args.exprs[1].name = basic_types[paramType][1]
							# format
							dump_from_mem.body.block_items[1].init.args.exprs[2].name = '"%s"' % basic_types[paramType][0]

							syscalls.ext.append(dump_from_mem)

# dump_param_template = self.generate_dump_param_call("ptr", get_register.name,
# 													singleParam=True, size=basic_types["ptr"][2],
# 													from_where="_from_mem")

# dump_from_mem_text = r"""
# int dump_type_from_mem(unsigned int addr, char **param_str, unsigned int size, struct target* target){
# 	unsigned int *value = get_address_value(target, addr, size);
# 	int snprintf_n_read = snprintf(*param_str, __num_chars, __format, *value);
# 	free(value);
# 	return snprintf_n_read;
# }
# """

# 					dump_complex_type = parser.parse(dump_complex_type_template, filename='<none>').ext[0]

# 					dump_complex_type.decl.name 				= "dump_" + paramType
# 					dump_complex_type.decl.type.type.declname	= "dump_" + paramType

# 					if isPtrStruct(params[0]):
# 						#print("STRUCT: %s" % paramType)
# 						v = DeclVisitor(paramType)
# 					else:
# 						#print("TYPEDEF: %s" % paramType)
# 						v = DeclTypedef(paramType)

# 					# holds the max depth level for param
# 					param_deref = 0
# 					aux = params[0]
# 					while isPtr(aux):
# 						aux = aux.type
# 						param_deref += 1
# 					print("param_deref: %s" % param_deref)

# # get_address_value_template_text = r"""
# # unsigned int *value = get_address_value(target, __addr, __size);
# # """

# # dump_from_mem_text = r"""
# # int dump_type_from_mem(unsigned int addr, char **param_str, unsigned int size){
# # 	unsigned int *value = get_address_value(target, addr, size);
# # 	int snprintf_n_read = snprintf(*param_str, __num_chars, __format, *value);
# # 	return snprintf_n_read;
# # }
# # """
# 					# add dump_address_from_mem if unexistent
# 					dump_param_template = self.generate_dump_param_call("Ptr", get_register.name,
# 																		hasDepth=0, singleParam=True, 
# 																		from_where="_from_reg")

# 					j = 1
# 					while j < param_deref:

# 						param_deref -= 1

# 					#block_items_param_deref = dump_complex_type.body.block_items[2].iffalse.block_items

# 					# len += dump_pollfd, for example
# 					v.visit(structs)
# 					types = v.get_var_types()

# 					block_items_dump = dump_complex_type.body.block_items[2].iffalse.iffalse.block_items
# 					block_items_dump[0].rvalue.args.exprs[0].left.name	= str(len(types))
# 					block_items_dump[1].rvalue.args.exprs[1].name		= str(len(types))
# 					block_items_dump[2].args.exprs[1].name				= str(len(types))

# 					block_items_dump_cp = block_items_dump[:]

# 					block_items_list = []
# 					i				= 0
# 					offset			= 0
# 					act_max_deref	= int(dump_complex_type.body.block_items[2].iffalse.cond.right.value)

# 					print(types)
# 					# get max deref
# 					for typ in types:
# 						typ = typ.replace('*STRUCT', '*')
# 						# Assumption: struct can be read as *
# 						typ = typ.replace('STRUCT', '*')
# 						print(typ)

# 						j = 0
# 						dump_iffalse = dump_complex_type.body.block_items[2].iffalse
# 						while typ[0] == "*":
# 							if act_max_deref < j:
# 								act_max_deref = j
# 								if_template = c_ast.If(
# 														c_ast.BinaryOp('==', c_ast.ID('depth'), c_ast.Constant('int', str(act_max_deref))),
# 														c_ast.Compound(block_items_dump_cp),
# 														dump_iffalse.iffalse
# 													  )
# 								dump_iffalse.iffalse = if_template
# 								dump_iffalse = dump_iffalse.iffalse
# 							j += 1
# 							typ = typ[1:]
# 						print("j-1: %s" % (j-1))

# 					print("%s: %s" % (params[0].name, act_max_deref))

# 					# dump_iffalse = dump_complex_type.body.block_items[2].iffalse
# 					# j = 0
# 					# while j < act_max_deref:
# 					# 	block_items_list.append(dump_iffalse.iftrue.block_items)
# 					# 	dump_iffalse = dump_iffalse.iffalse

# 					# for typ in types:
# 					# 	old_typ = typ
# 					# 	typ = typ.replace('*STRUCT', '*')
# 					# 	# Assumption: struct can be read as *
# 					# 	typ = typ.replace('STRUCT', '*')
# 					# 	j = 0
# 					# 	dump_iffalse = dump_complex_type.body.block_items[2].iffalse
# 					# 	while typ[0] == "*":
# 					# 		if act_max_ptr < str(j):
# 					# 			act_max_ptr = str(j)
# 					# 			if_template = c_ast.If(
# 					# 									c_ast.BinaryOp('==', c_ast.ID('depth'), c_ast.Constant('int', str(j))),
# 					# 									c_ast.Compound(block_items_dump_cp),
# 					# 									dump_iffalse.iffalse
# 					# 								  )
# 					# 			dump_iffalse.iffalse = if_template
# 					# 			dump_iffalse = dump_iffalse.iffalse
# 					# 			block_items_list.append(dump_iffalse.iftrue.block_items)
# 					# 		j += 1
# 					# 		typ = typ[1:]

# 					# 	print("\nLISTT: %s\n" % block_items_list)
# 					# 	print("\nLISTT: %s\n" % block_items_dump)


# 					# 	if typ in basic_types:
# 					# 		print("yes: %s %s" % (typ, typ==old_typ))
# 					# 		# TODO: addr + sizeof(var)
# 					# 		dump_param_template = self.generate_dump_param_call(typ, "addr+" + str(offset),
# 					# 															hasDepth=True,
# 					# 															from_where="_from_reg",
# 					# 															index=i, dumped_name=dump_complex_type.body.block_items[0].name)
# 					# 		offset += basic_types[typ][2]
# 					# 		for blocks in block_items_list:
# 					# 			blocks.insert(1+i, dump_param_template) # insert dump_param_template call before return
# 					# 		block_items_dump.insert(1+i, dump_param_template) # insert dump_param_template call before return
# 					# 	else:
# 					# 		print("no: %s %s" % (typ, typ==old_typ))
# 					# 	i += 1
# # v = DeclTypedef('time_t')
# # v.visit(structs_template)
# # types = v.get_var_types()
# # print(types)

# # v = DeclVisitor('pollfd')
# # v.visit(structs_template)

# # types = v.get_var_types()
# # # for i in xrange(len(types)):
# # # 	if "St " in types[i]:
# # # 		v.set_var_types(types[i][2:], i)
# # print(types)

# 					# # nr_params = 1
# 					# block_items_dump[0].rvalue.args.exprs[0].left.name	= "1"
# 					# block_items_dump[1].rvalue.args.exprs[1].name		= "1"
# 					# block_items_dump[2].args.exprs[1].name				= "1"
				else:
					print("IS NOT BASIC TYPE AND DOES NOT HAVE PTR")

				for block_item in block_items:
					node.body.block_items.append(block_item)
				node.decl.type.args.params = dump_sys.decl.type.args.params
				return



			# multiple params
			# if True deletes "depth" from the dump function call
					# nr_params = 1
					# block_items[3].rvalue.args.exprs[0].left.name	= "1"
					# block_items[4].rvalue.args.exprs[1].name		= "1"
					# block_items[5].args.exprs[1].name				= "1"
			# single_param.body.block_items.insert(4, generate_dump_param_call(param, hasDepth=True))
			i = 0
			for param in params:
				isBasicType(param)

				get_register = self.generate_get_register(param, i)
				node.body.block_items.append(get_register)
				i += 1

			node.decl.type.args.params = []

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
		if isStruct(param.type) == False: # is Identifier Type, hopefully
			paramType = "_".join(param.type.type.names)
			if paramType in basic_types:
				return True
		elif isStruct(param.type):
			return False
		else:
			print("[isBasicType] SHOULD NOT HAPPEN")
	return False

def isPtr(param):
	return type(param.type) == c_ast.PtrDecl

def isStruct(param):
	return type(param.type) == c_ast.Struct

def isPtrStruct(param):
	while isPtr(param):
		param = param.type

	return isStruct(param.type)

def get_type_from_typedecl(typedecl, sep="_"):
	paramType = ""

	if type(typedecl.type) == c_ast.IdentifierType:
		paramType = sep.join(typedecl.type.names)
	elif type(typedecl.type) == c_ast.Struct:
		paramType = typedecl.type.name
	else:
		print("[get_type_from_typedecl] SHOULD NOT HAPPEN")

	return paramType

class DeclVisitor(c_ast.NodeVisitor):
	def __init__(self, struct_name):
		self.struct_name = struct_name
		self.var_types = []

	def get_var_types(self):
		return self.var_types

	def set_var_types(self, new_type, ix):
		self.var_types[ix] = new_type

	def set_types_from_typedecl(self, typedecl, pref=""):
		types = ""
		if type(typedecl.type) == c_ast.IdentifierType:
			types = pref + "_".join(typedecl.type.names)
		elif isStruct(typedecl):
			types = pref + "STRUCT" + typedecl.type.name
		else:
			print("[set_types_from_typedecl] SHOULD NOT HAPPEN")
		self.var_types.append(types)

	def visit_Decl(self, node):
		if type(node.type) == c_ast.Struct:
			if node.type.name == self.struct_name:
				for var in node.type.decls:
					if type(var.type) == c_ast.TypeDecl:
						self.set_types_from_typedecl(var.type)
						# self.var_types[-1].append(var.name)
					elif isPtr(var):
						if type(var.type.type) == c_ast.TypeDecl:
							self.set_types_from_typedecl(var.type.type, "*")
							# self.var_types[-1].append(var.name)
						elif isPtr(var.type): # double ptrs
							self.set_types_from_typedecl(var.type.type.type, "**")
							# self.var_types[-1].append(var.type.type.type.declname)
							# TODO: do not ignore more than 2ptrs
						else:
							print("[visit_Decl:1] SHOULD NOT HAPPEN")
					else:
						print("[visit_Decl:2] SHOULD NOT HAPPEN")


class DeclTypedef(c_ast.NodeVisitor):
	def __init__(self, typedef_name):
		self.typedef_name	= typedef_name
		self.var_types		= []

	def get_var_types(self):
		return self.var_types

	def reset_var_types(self):
		del self.var_types[:]

	def visit_Typedef(self, node):
		if node.name == self.typedef_name:
			if type(node.type) == c_ast.TypeDecl:
				if type(node.type.type) == c_ast.IdentifierType:
					self.var_types.append(node.type.type.names[0])
				elif type(node.type.type) == c_ast.Struct:
					for decl in node.type.type.decls:
						self.var_types.append(decl.type.type.names[0])

# TODO add num of chars to define
# name: [str_format, number of digits (plus sign and \0), size of each var on target arch]
basic_types =	{
				'long': ["%li", "NUM_CHARS_LONG", 4],
				'int': ["%d", "NUM_CHARS_INT", 4],
				'short': ["%hi", "NUM_CHARS_SHORT", 2], 
				'unsigned_long': ["%lu", "NUM_CHARS_ULONG", 4],
				'unsigned_int': ["%u", "NUM_CHARS_UINT", 4],
				'unsigned_short': ["%hu", "NUM_CHARS_USHORT", 2],
				'unsigned': ["%u", "NUM_CHARS_UNSIGNED", 4],
				'ptr': ["%x", "NUM_CHARS_PTR", 4]
				}

syscalls	= parser.parse(syscalls_text, filename='<none>')
structs		= parser.parse(structs_text, filename='<nome>')

v = FuncDefVisitor()
v.visit(syscalls)

print("after:")
print(generator.visit(syscalls))
