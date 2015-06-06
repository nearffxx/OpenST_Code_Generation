from __future__ import print_function
import sys

sys.path.extend(['.', '..'])

from pycparser import c_generator, c_parser, c_ast
parser = c_parser.CParser()
generator = c_generator.CGenerator()

text = r"""
struct st{
	int a;
	int b;
};
int sys_test(struct st st1)
{
	int a;
}

int normal()
{}
"""

mycode_text = r"""
func() {
 struct _struct_name *_name = malloc(_size);
}
"""
mycode = parser.parse(mycode_text, filename='<none>')
ast = parser.parse(text, filename='<none>')



print("before:")
print(generator.visit(ast))
	
class FuncDefVisitor(c_ast.NodeVisitor):
    def visit_FuncDef(self, node):
	if "sys_" in node.decl.name:
		node.decl.name = "dump_" + node.decl.name
		node.decl.type.type.declname = "dump_" + node.decl.type.type.declname
		# malloc
		mycode.ext[0].body.block_items[0].name = node.decl.type.args.params[0].name
		mycode.ext[0].body.block_items[0].type.type.declname = node.decl.type.args.params[0].type.declname
		mycode.ext[0].body.block_items[0].type.type.type = node.decl.type.args.params[0].type.type

		node.body.block_items.append(mycode.ext[0].body.block_items[0])
		node.decl.type.args.params = []
		#.append(node.decl.type.args.params[0])

v = FuncDefVisitor()
v.visit(ast)

print("after:")
print(generator.visit(ast))

