from __future__ import print_function
import sys

sys.path.extend(['.', '..'])

from pycparser import parse_file, c_generator, c_parser, c_ast
parser = c_parser.CParser()
generator = c_generator.CGenerator()

mycode_text = r"""
typedef int xxx;

struct _timespec {
 xxx tv_sec;
 long int tv_nsec;
};
"""
ast = parse_file("sys.h", use_cpp=True)
mycode = parser.parse(mycode_text, filename='<none>')

mycode.show()
