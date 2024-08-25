import os
import sys
import re
sys.path.insert(0, os.path.abspath("../../"))
from ChatAnalyzer.extract_func_body import extract_func_definition_linerange_linux_path
from ChatAnalyzer.get_arguments import get_funcname_firstline_linux_folder

project_root = "/home/clexma/Desktop/fox3/fuzzing/"
linux_folder = project_root + "linuxRepo/"

def process_line(line):
    # Regular expression to match the three parts
    match = re.match(r'(\d+)?\s*(0x[0-9a-f]+|ffffffff[0-9a-f]+)?\s*(.*)', line.strip())
    
    if match:
        part1 = match.group(1) if match.group(1) else ""
        part2 = match.group(2) if match.group(2) else ""
        part3 = match.group(3).strip() if match.group(3) else ""
        return part1, part2, part3
    else:
        return "", "", ""


def obtain_function_addresses(line_range, file_path):
    line2addr_command = "./line2addr.py -b " + linux_folder + "/linux_new/vmlinux -f " + file_path  + " > ./working_folder/temp_result.txt"
    trimming_command = "sed 's/\x1b\[[0-9;]*m//g' ./working_folder/temp_result.txt > ./working_folder/result.txt"
    if os.path.exists("./working_folder/result.txt"):
        pass
    else:
        os.system(line2addr_command)
        os.system(trimming_command)
    trimmed_file = open("./working_folder/result.txt", "r+")
    relative_addressese = dict()
    most_recent_part1 = ""
    most_recent_part3 = ""
    in_range = False
    print("line range: ")
    print("from: " + str(line_range[0]) + " " + "to: " + str(line_range[1]))
    for line in trimmed_file.readlines():
        part1, part2, part3 = process_line(line)
        # print(part1 + " " + part2 + " " + part3)
        most_recent_part1 = part1
        if part3 != "":
            most_recent_part3 = part3
        if most_recent_part1 == "":
            pass
        else:
            line_number = int(part1)    
            if line_number >= line_range[0] and line_number <= line_range[1]:
                in_range = True
            else:
                in_range = False
        if in_range:
            if part2 != "":
                # print("collect line address")
                if most_recent_part3 in relative_addressese:
                    relative_addressese[most_recent_part3].add(part2)
                else:
                    new_set = set()
                    new_set.add(part2)
                    relative_addressese[most_recent_part3] = new_set
    # print("print all address: ")
    # for item in relative_addressese:
    #     print(item)
        # for item_addr in relative_addressese[item]:
            # print(item_addr)
            # pass
    return relative_addressese
            




if __name__ == "__main__":
    #  1. obtain target function and close functions from the input
    #  2. extract address in target functions and close functions:
                # (1) determine the files of the functions
                # (2) process the file with vmlinux and process the files
                # (3) obtain the address from the files process
                # (4) export the adresses to an independent file (export it to folder in syzkaller)
    input_file_name = sys.argv[1]
    input_file = open(input_file_name, "r")
    close_functions = set()
    close_file_paths = set()
    pc_points = set()
    for line in input_file.readlines():
        func_name_line = line.strip().replace("\n", "")
        close_functions.add(func_name_line)
    output_file_name = "./func2addr_info.txt"
    output_file = open(output_file_name, "a+")

    pure_addr_output_file_name = "./result_addr_info.txt"
    pure_addr_output_file = open(pure_addr_output_file_name, "a+")

    # determine the files of the function
    for function_name in close_functions:
        first_line_result = get_funcname_firstline_linux_folder(function_name, linux_folder)
        file_path = first_line_result[0]
        print("current function name file path: " + file_path)
        line_range = extract_func_definition_linerange_linux_path(function_name, linux_folder)
        line_addr_map = obtain_function_addresses(line_range, file_path)
        os.system("rm ./working_folder/*")
        for item in line_addr_map:
            output_file.write("----- funcname:\n")
            output_file.write(function_name + "\n")
            output_file.write("----- filepath:\n")
            output_file.write(file_path + "\n")
            output_file.write("----- addresses:\n")
            for addr in line_addr_map[item]:
                output_file.write(addr + "\n")
                pure_addr_output_file.write(addr + "\n")

        

        



    






        