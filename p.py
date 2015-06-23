from __future__ import print_function
import sys

sys.path.extend(['.', '..'])

from pycparser import parse_file, c_generator, c_parser, c_ast
parser = c_parser.CParser()
generator = c_generator.CGenerator()

mycode_text = r"""
func() {
 struct _struct_name *_name = malloc(_size);
}
"""
ast = parse_file("sys.h", use_cpp=True)
mycode = parser.parse(mycode_text, filename='<none>')


