import argparse
import os
import sys
import yara
import json
from magika import Magika

def generate_index_file(category):
    cwd = os.getcwd()
    dir_path = os.path.join(cwd, category)
    if(os.path.isdir(dir_path)):
        done_files = []
        for (dirpath, dirnames, filenames) in os.walk(dir_path):
            done_files.extend(filenames)
            break
        for i in done_files:
            file_name = category+'_index.yar'
            with open(file_name, 'a') as f:
                f.write('include "'+os.path.join(dir_path,i)+'"\n')

    else:
        print('Category {} is not found in the current working directory'.format(category))

def yara_matches(mat):
    match = []
    if(len(mat)> 0):
        for index in mat:
            match.append(index.rule)
    return match



def main():
    parser = argparse.ArgumentParser(description="Yara Rules")
    parser.add_argument("-i", "--index", help="Generate the index file for the yara rules.", action='store_true')
    parser.add_argument("-c", "--category", help="Match the yara rules as per categorization.", type=str)
    parser.add_argument("-f", "--filename", help="File to match the yara rules", type=str)
    parser.add_argument("-o", "--output_file", help="Output the result in json file", type=str)
    args = parser.parse_args()

    cat = {'android': {'apk', 'aab', 'smali'}, 
            'windows': {'pebin', 'msi', 'powershell', 'javascript', 'asm', 'vba', 'pdf', 'lnk', 'cs', 'hlp', 'ico', 'ini', 'odp', 'ods', 'odt', 'outlook', 'pdf', 'postscript', 'ppt', 'pptx','pptm', 'doc', 'docx', 'pptm', 'xls', 'xlx', 'xlsx', 'xlm'},
            'linux': {'symlink', 'shell', 'sh', 'so', 'elf'},
            'packers': {},
            'detection': {},
            'macos': {'appleplist', 'batch', 'dmg', 'macho'}}
    if(args.index):
        for cate in cat:
            generate_index_file(cate)

    if(args.filename):
        m = Magika()
        with open(args.filename, 'rb') as f:
            content = f.read()

        response = m.identify_bytes(content)
        file_ext = ''
        if(response.output.ct_label == response.dl.ct_label):
            file_ext = response.output.ct_label
        else:
            file_ext = response.dl.ct_label

        if(file_ext):
            if(args.category):
                rules_matches = {}
                if(file_ext in cat[args.category]):
                    path = os.path.join(os.getcwd(), args.category+'_index.yar')
                    rules = yara.compile(path)
                    mat = rules.match(args.filename)

                    rules_matches[args.category] = yara_matches(mat) 

                    detection_path = os.path.join(os.getcwd(), 'detection_index.yar')
                    rules = yara.compile(detection_path)
                    mat = rules.match(args.filename)

                    rules_matches['Yara_detection_matches'] = yara_matches(mat) 
                    
                    packer_path = os.path.join(os.getcwd(), 'packers_index.yar')
                    rules = yara.compile(packer_path)
                    mat = rules.match(args.filename)

                    rules_matches['Yara_packer_matches'] = yara_matches(mat)
                
                else:
                    print("We don't have rules for this file type {} in this file category {}".format(file_ext, args.category))
                
                if(args.output_file):
                    with open(args.output_file, 'w') as f:
                        json.dump(rules_matches, f)
                else:
                    print(rules_matches)

            else:
                print("You haven't mentioned the category like for which operating system you want to check the files.")



if __name__ == "__main__":
    main()
