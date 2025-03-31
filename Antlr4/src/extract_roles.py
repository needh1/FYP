import os
import re
import csv
from collections import defaultdict
#from tqdm import tqdm
from ast_generator import parse_with_ast  # presumably in your code


# We focus on matching functions with a body and public/external
function_pattern = re.compile(
    r"""
    function
    \s+([^\s({]+)                      # func name
    \s*\(([^)]*)\)                     # parameters
    \s+(public|external                # visibility is mandatory
        (?:\s+(?:view|pure|payable))*)? # optionally view/pure/payable
    \s*(returns\s*\([^\)]*\))?         # optional 'returns(...)'
    \s*\{([\s\S]*?)\}                  # function body
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE
)

modifier_pattern = re.compile(
    r"modifier\s+([^\s(]+)\s*\((.*?)\)?\s*\{(.*?)\}",
    re.DOTALL
)

require_pattern = re.compile(
    r"require\((.*?)\)",
    re.DOTALL
)

conditional_pattern = re.compile(
    r'\bif\s*\(\s*(!?hasRole\([^)]*\)|msg\.sender\s*(==|!=)\s*\w+)\)\s*(revert|throw)\b',
    re.IGNORECASE
)

enhanced_role_patterns = [
    r'hasRole\((.*?),(.*?)\)',      # e.g. hasRole(MINTER_ROLE, msg.sender)
    r'onlyRole\((.*?)\)',           # e.g. onlyRole(MINTER_ROLE)
    r'require\s*\(\s*msg\.sender\s*==\s*(\w+)',  # e.g. require(msg.sender == owner)
    r'require\s*\(\s*(\w+)\(msg\.sender\)',      # e.g. require(isAdmin(msg.sender))
]

role_keywords = [
    'admin', 'owner', 'manager', 'controller',
    'minter', 'burner', 'pauser', 'upgrader',
    'vault', 'treasurer', 'guardian'
]

role_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in enhanced_role_patterns]

role_mapping_patterns = [
    r'mapping\(\w+\s*=>\s*bool\)\s+(\w+)Role',
    r'mapping\(address\s*=>\s*bool\)\s+(\w+)Roles'
]


def enhanced_role_detection(code, path):
    """
    This function tries to detect role usage in the entire code,
    not just within a single function. E.g. role mappings, etc.
    """
    roles_permissions = []
    
    # We'll search for known role-based patterns in the entire code
    # (Though you might prefer focusing on function by function)
    
    for role_map_pattern in role_mapping_patterns:
        map_matches = re.findall(role_map_pattern, code, re.IGNORECASE)
        for m in map_matches:
            roles_permissions.append((path, "RoleMapping", "", f"mapping_based:{m}"))
    
    return roles_permissions

def extract_info(code, path):
    """
    Using the specialized function_pattern that
    only captures public/external with a body.
    Then search for require statements, inline if checks, etc.
    """
    roles_permissions = []
    
    func_matches = function_pattern.findall(code)
    for func_match in func_matches:
        if len(func_match) < 5:
            # pad with empty strings
            func_match = func_match + ("",) * (5 - len(func_match))
        else:
            # or truncate if too many (rare)
            func_match = func_match[:5]
        func_name, params, visibility, returns_clause, body = func_match

        if not body.strip():
            # Possibly an empty body => skip
            continue
        
        # Next, check for modifiers or require statements in the body
        # 1) If there's a local modifier definition in the body
        mod_in_body = modifier_pattern.search(body)
        if mod_in_body:
            roles_permissions.append((
                path, "Modifier", func_name.strip(), mod_in_body.group(1)
            ))
        
        # 2) Check if function contains require statement
        req_in_body = require_pattern.findall(body)
        for req_expr in req_in_body:
            roles_permissions.append((
                path, "Require", func_name.strip(), req_expr
            ))
        
        # 3) Check inline if conditions
        custom_if_matches = conditional_pattern.findall(body)
        for match in custom_if_matches:
            # match might look like: ("!hasRole(...)", "==", "revert") etc.
            # We'll store them as a single string
            roles_permissions.append((
                path, "InlineIfCheck", func_name.strip(),
                f"Condition: {match[0]} op={match[1]} action={match[2]}"
            ))
        
        # 4) Enhanced role regex check
        detected_roles = []
        # a) Check function name for role keywords
        for keyword in role_keywords:
            if keyword.lower() in func_name.lower():
                detected_roles.append(f"name_based:{keyword}")
        
        # b) Check the body for patterns
        for rr in role_regexes:
            founds = rr.findall(body)
            for fnd in founds:
                if isinstance(fnd, tuple):
                    # e.g. hasRole(...) capturing multiple groups
                    for piece in fnd:
                        if piece.strip():
                            detected_roles.append(f"regex_based:{piece.strip()}")
                else:
                    detected_roles.append(f"regex_based:{fnd.strip()}")
        
        # c) If we found any "detected_roles", add them
        if detected_roles:
            unique_roles = list(set(detected_roles))
            roles_permissions.append((
                path, "Enhanced", func_name.strip(),
                ", ".join(unique_roles)
            ))
    
    # Also run the "enhanced_role_detection" for broader checks (mappings, etc.)
    broader = enhanced_role_detection(code, path)
    roles_permissions.extend(broader)
    
    return roles_permissions


def extract_info_with_ast_and_regex(file_path):
    # We'll read code here, pass it to both approaches
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()
    
    # 1) Regex approach
    regex_results = extract_info(code, file_path)
    
    # 2) AST approach
    ast_summary = parse_with_ast(file_path)  # uses your other module
    ast_results = []
    functions_data = ast_summary.get("functions", {})
    
    for fn_name, fn_info in functions_data.items():
        if fn_info.get("is_vulnerable"):
            rc_list = fn_info.get("role_checks", [])
            modifiers_list = fn_info.get("modifiers", set())
            
            # First, check for explicit role checks
            if rc_list:
                # store each role check
                for rc in rc_list:
                    ast_results.append((file_path, 'AST_RoleCheck', fn_name, rc))
            
            # Next, check for modifiers - this is the key change
            elif modifiers_list:
                # If the function has modifiers but no explicit role checks,
                # report the modifiers instead of "NoRoleCheck"
                for modifier in modifiers_list:
                    ast_results.append((file_path, 'AST_Modifier', fn_name, modifier))
            else:
                # No role checks or modifiers => "NoRoleCheck"
                ast_results.append((file_path, 'NoRoleCheck', fn_name, 'Vulnerable function lacks roles'))
    
    combined = regex_results + ast_results
    
    # Use a set for uniqueness
    unique_records = set(combined)
    return list(unique_records)


def check_openzeppelin_import(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    
    openzeppelin_access_controls = [
        "import '@openzeppelin/contracts/access/Ownable.sol';",
        "import '@openzeppelin/contracts/access/AccessControl.sol';",
        "import '@openzeppelin/contracts/access/AccessControlEnumerable.sol';",
        "import '@openzeppelin/contracts/access/RoleBasedAccessControl.sol';",
    ]
    for line in openzeppelin_access_controls:
        if line in content:
            return True
    return False


def extract_roles_from_eth():
    output_csv = 'Roles/roles_permissions.csv'
    
    # Open once, keep writing
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Path', 'Type', 'Functions', 'Role', 'isOZ'])

        c = 0
        for root, dirs, files in os.walk('./Data'):
            for file in files:
                if file.endswith('.sol'):
                    c +=1
                    print(c, '\r', end='', flush=True)
                    path = os.path.join(root, file)
                    
                    combined_info = extract_info_with_ast_and_regex(path)
                    is_oz = check_openzeppelin_import(path)
                    
                    for item in combined_info:
                        # item is (path, type, functionName, roleData)
                        row = list(item) + [str(is_oz)]
                        writer.writerow(row)


def is_alphanumeric(s):
    return s.isalnum()

def is_nonsense(s):
    return re.match('[o|O]nly\d+', s) is not None

def clean_output_file():
    counts = defaultdict(int)
    
    with open('Roles/roles_permissions.csv', 'r', encoding='utf-8') as f_in, \
         open('Roles/roles_permissions_clean.csv', 'w', encoding='utf-8', newline='') as f_out:
        
        writer_out = csv.writer(f_out)
        writer_out.writerow(['Role', 'Functions'])
        
        for line in csv.reader(f_in):
            # line ~ [Path, Type, Function, Role, isOZ]
            if len(line) < 4:
                continue
            
            detail = line[3]  # the 'Role' column in your older code
            if not detail.strip():
                continue
            
            # if not is_alphanumeric(detail):   # you might remove or refine
            #     continue
            if is_nonsense(detail):
                print("Skipping nonsense:", line)
                continue
            
            # Expand detection beyond 'only' or 'role'
            # We'll consider lines that have 'only', 'role', or 'msg.sender', 'hasRole' etc.
            lowers = detail.lower()
            if any(keyword in lowers for keyword in ['only','role','msg.sender','hasrole','admin','owner']):
                # We'll store them as: (Role, Function)
                # e.g. "regex_based:owner [Placeholder] mint"
                # Your code uses [Placeholder] so let's do that
                # We'll parse out the function from line[2]
                func_name = line[2]
                # We'll parse out the "role" from detail in a naive way
                # or just store them raw
                # For your code, you do: role, func = key.split('[Placeholder]')
                # We'll do something simpler here:
                
                # We'll store them exactly
                # e.g. counts[detail + '[Placeholder]' + func_name] += 1
                counts[detail + '[Placeholder]' + func_name] += 1
        
        # Now write them out
        for key, count in counts.items():
            # key might be "regex_based:owner[Placeholder]mint"
            if '[Placeholder]' in key:
                role_str, func_str = key.split('[Placeholder]')
                writer_out.writerow([role_str, func_str, count])
            else:
                # fallback
                writer_out.writerow([key, "", count])


def process_output():
    roles = {}
    with open('Roles/roles_permissions_clean.csv', 'r', encoding='utf-8') as f:
        for line in csv.reader(f):
            if line[0] == 'Role':
                continue
            if len(line) < 2:
                continue
            role_part = line[0].lower()
            func_part = line[1]
            
            # If the role starts with 'only'
            if role_part.startswith('only'):
                role_key = role_part.replace('only','').strip()
            else:
                role_key = role_part
            
            roles[role_key] = func_part  # you might have collisions overwriting here
            
    # Write final
    with open('Roles/roles_permissions_processed.csv', 'w', encoding='utf-8', newline='') as fw:
        writer = csv.writer(fw)
        writer.writerow(['role','functions'])
        for rkey, fval in roles.items():
            writer.writerow([rkey, fval])
    print(roles.keys())


if __name__ == '__main__':
    extract_roles_from_eth()
    clean_output_file()
    process_output()
