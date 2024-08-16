import os
import sys
sys.path.append("../ChatAnalyzer")
from ChatAnalyzer.get_arguments import get_funcname_firstline_linux_folder
from ChatAnalyzer.extract_func_body import extract_func_definition_linerange_linux_path


linux_folder = "../linux_new"

def obtain_function_addresses(line_range, file_path):
    line2addr_command = "./line2addr.py -b " + linux_folder + "/vmlinux -f " + file_path  + " > ./working_folder/temp_result.txt"
    trimming_command = "sed 's/\x1b\[[0-9;]*m//g' ./working_folder/temp_result.txt > ./working_folder/result.txt"
    os.system(line2addr_command)
    os.system(trimming_command)
    trimmed_file = open("./working_folder/result.txt", "r+")
    for line in trimmed_file.readlines():
        print(line)



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
    close_file_paths = set()
    pc_points = set()
    for line in file.readlines():
        func_name_line = line.strip().replace("\n", "")
        close_functions.add(func_name_line)
    
    # determine the files of the function
    for function_name in close_functions:
        first_line_result = get_funcname_firstline_linux_folder(function_name, linux_folder)
        file_path = first_line_result[0]
        print("current function name file path: " + file_path)
        line_range = extract_func_definition_linerange_linux_path(function_name, linux_folder)
        obtain_function_addresses(line_range, file_path)
        



    






        