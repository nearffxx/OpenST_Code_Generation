# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/nearffxx/parser/pahole

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/nearffxx/parser/pahole/build

# Include any dependencies generated for this target.
include CMakeFiles/syscse.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/syscse.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/syscse.dir/flags.make

CMakeFiles/syscse.dir/syscse.o: CMakeFiles/syscse.dir/flags.make
CMakeFiles/syscse.dir/syscse.o: ../syscse.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/nearffxx/parser/pahole/build/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object CMakeFiles/syscse.dir/syscse.o"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/syscse.dir/syscse.o   -c /home/nearffxx/parser/pahole/syscse.c

CMakeFiles/syscse.dir/syscse.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/syscse.dir/syscse.i"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -E /home/nearffxx/parser/pahole/syscse.c > CMakeFiles/syscse.dir/syscse.i

CMakeFiles/syscse.dir/syscse.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/syscse.dir/syscse.s"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -S /home/nearffxx/parser/pahole/syscse.c -o CMakeFiles/syscse.dir/syscse.s

CMakeFiles/syscse.dir/syscse.o.requires:
.PHONY : CMakeFiles/syscse.dir/syscse.o.requires

CMakeFiles/syscse.dir/syscse.o.provides: CMakeFiles/syscse.dir/syscse.o.requires
	$(MAKE) -f CMakeFiles/syscse.dir/build.make CMakeFiles/syscse.dir/syscse.o.provides.build
.PHONY : CMakeFiles/syscse.dir/syscse.o.provides

CMakeFiles/syscse.dir/syscse.o.provides.build: CMakeFiles/syscse.dir/syscse.o

# Object files for target syscse
syscse_OBJECTS = \
"CMakeFiles/syscse.dir/syscse.o"

# External object files for target syscse
syscse_EXTERNAL_OBJECTS =

syscse: CMakeFiles/syscse.dir/syscse.o
syscse: CMakeFiles/syscse.dir/build.make
syscse: libdwarves.so.1.0.0
syscse: CMakeFiles/syscse.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C executable syscse"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/syscse.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/syscse.dir/build: syscse
.PHONY : CMakeFiles/syscse.dir/build

CMakeFiles/syscse.dir/requires: CMakeFiles/syscse.dir/syscse.o.requires
.PHONY : CMakeFiles/syscse.dir/requires

CMakeFiles/syscse.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/syscse.dir/cmake_clean.cmake
.PHONY : CMakeFiles/syscse.dir/clean

CMakeFiles/syscse.dir/depend:
	cd /home/nearffxx/parser/pahole/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/nearffxx/parser/pahole /home/nearffxx/parser/pahole /home/nearffxx/parser/pahole/build /home/nearffxx/parser/pahole/build /home/nearffxx/parser/pahole/build/CMakeFiles/syscse.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/syscse.dir/depend
