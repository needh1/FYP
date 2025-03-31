import csv
import json


def read_dataset(path):
    ret = {}
    with open(path, newline='') as f:
        reader = csv.reader(f)
        header = next(reader)  # Skip the header row
        for line in reader:
            ret[line[0].strip()] = {
                'file': line[1].strip(),
                'class': line[2].strip(),
                'function': line[3].strip(),
                'description': line[4].strip()
            }
    return ret

def get_gpt_template():
    gpt = json.load(open('Data/gpt_template.json'))
    # gpt['evidence']['role_category'] = json.load(open('data/role/Pre-study - Roles&Permissions.json'))
    # gpt['evidence']['templates'] = json.load(open('data/role/Pre-study - Templates.json'))
    return gpt