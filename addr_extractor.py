import os
import sys

from ChatAnalyzer.get_arguments import get_funcname_firstline_linux_folder
sys.path.append("..")

linux_folder = "../linux_new"

if __name__ == "__main__":
    # TODO: 1. obtain target function and close functions from the input
    # TODO: 2. extract address in target functions and close functions:
                # (1) determine the files of the functions
                # (2) process the file with vmlinux and process the files
                # (3) obtain the address from the files process
                # (4) export the adresses to an independent file (export it to folder in syzkaller)
    input_file_name = sys.argv[1]
    file = open(input_file_name, "r")
    close_functions = set()
    pc_points = set()
    for line in file.readlines():
        func_name_line = line.strip().replace("\n", "")
        close_functions.add(func_name_line)
    
    # determine the files of the function
    for function_name in close_functions:
        path_result = get_funcname_firstline_linux_folder(function_name, linux_folder)
        



        