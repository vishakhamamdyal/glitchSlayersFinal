import os
import json
import yaml
import subprocess
import tempfile
import shutil
import stat
import re 
from git import Repo
from openai import AzureOpenAI
from datetime import datetime

# Azure OpenAI Setup
endpoint = "https://bh-in-openai-glitchslayers.openai.azure.com/"
model_name = "gpt-35-turbo"
deployment = "gpt-35-turbo"
subscription_key = "c093c3a427f04210967aed6d3f7e5ba3"
api_version = "2024-12-01-preview"
BRANCH_NAME = f"cft-security-fixes-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

client = AzureOpenAI(
    api_version=api_version,
    azure_endpoint=endpoint,
    api_key=subscription_key,
)

# GitHub Configuration
GITHUB_REPO_URL = "https://github.com/vishakhamamdyal/glitchSlayers.git"
# BRANCH_NAME = "cft-vulnerabilities-2"

# Register CloudFormation custom tags

def register_cfn_tags():
    def tag_scalar(tag):
        return lambda loader, node: {tag: loader.construct_scalar(node)}

    def tag_sequence(tag):
        return lambda loader, node: {tag: loader.construct_sequence(node)}

    def tag_mapping(tag):
        return lambda loader, node: {tag: loader.construct_mapping(node)}

    tags = {
        '!Ref': 'Ref',
        '!Condition': 'Condition',
        '!GetAtt': 'Fn::GetAtt',
        '!Sub': 'Fn::Sub',
        '!Join': 'Fn::Join',
        '!Select': 'Fn::Select',
        '!Split': 'Fn::Split',
        '!Equals': 'Fn::Equals',
        '!If': 'Fn::If',
        '!Not': 'Fn::Not',
        '!And': 'Fn::And',
        '!Or': 'Fn::Or',
        '!FindInMap': 'Fn::FindInMap',
        '!ImportValue': 'Fn::ImportValue',
        '!Base64': 'Fn::Base64',
        '!Cidr': 'Fn::Cidr',
        '!Transform': 'Fn::Transform'
    }

    for tag, mapped in tags.items():
        if tag in ['!Join', '!Split', '!Select', '!Equals', '!If', '!Not', '!And', '!Or', '!FindInMap', '!Cidr']:
            yaml.add_constructor(tag, tag_sequence(mapped), Loader=yaml.SafeLoader)
        elif tag in ['!Transform']:
            yaml.add_constructor(tag, tag_mapping(mapped), Loader=yaml.SafeLoader)
        else:
            yaml.add_constructor(tag, tag_scalar(mapped), Loader=yaml.SafeLoader)

register_cfn_tags()

# Utility to scan template and return fixed version
def scan_with_azure_openai(template_dict, file_format):
    # prompt = f"Detect vulnerabilities in this CloudFormation template and return a secure version:\n\n{json.dumps(template_dict)}"
    best_practices = (
        "- Do not use wildcard permissions (avoid Action: '*', Resource: '*')\n"
        "- Do not hardcode secrets or passwords\n"
        "- Do not allow wide open ingress in Security Groups (avoid 0.0.0.0/0)\n"
        "- Disable AssignPublicIp unless absolutely necessary\n"
        "- Avoid hardcoding subnet and VPC IDs\n"
        "- Use IAM Instance Profiles to grant least-privilege access\n"
        "- Enable encryption for volumes and sensitive data\n"
        "- Enable logging and monitoring (e.g., CloudWatch Agent)\n"
        "- Use access control tags and define resource-level policies\n"
    )
    prompt = (
        f"You are a CloudFormation vulnerability fixer. you have to fix the template using the standard best practices"
        "Below are some key practices to follow:\n"
        f"{best_practices}\n"
        f"Given the following CloudFormation template, return only the fixed template in valid {file_format.upper()} format. "
        "Do not include explanations, comments, or any other text — just return the corrected template.\n\n"
        f"{json.dumps(template_dict) if file_format == 'json' else yaml.safe_dump(template_dict)}"
    )
    response = client.chat.completions.create(
        messages=[
            {"role": "system", "content": "You are a CloudFormation vulnerability detector and fixer."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=4096,
        temperature=0.3,
        top_p=1.0,
        model=deployment
    )
    print("..... file.....")
    tempres=response.choices[0].message.content
    response_new = re.sub(r"^```yaml\s*|```$", "", tempres.strip(), flags=re.MULTILINE)
    print(response_new)
    return response_new

# Recursively find all CFT files
def find_cft_files(repo_dir):
    cft_files = []
    for root, _, files in os.walk(repo_dir):
        for file in files:
            if file.endswith((".yaml", ".yml", ".json")):
                cft_files.append(os.path.join(root, file))
    return cft_files

# Read and parse the CFT template
def load_cft_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            if file_path.endswith(".json"):
                return json.load(f)
            else:
                return yaml.load(f, Loader=yaml.SafeLoader)
    except Exception as e:
        print(f"❌ Failed to read {file_path}: {e}")
        return None

# Write updated CFT back to file
def save_fixed_template(file_path, fixed_content):
    try:
        if file_path.endswith(".json"):
            parsed = json.loads(fixed_content)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(parsed, f, indent=2)
        else:
            parsed = yaml.safe_load(fixed_content)
            with open(file_path, 'w', encoding='utf-8') as f:
                yaml.safe_dump(parsed, f, sort_keys=False)
        return True
    except Exception as e:
        print(f"❌ Failed to write fixed template to {file_path}: {e}")
        return False

# Git: Clone and create branch
def setup_repo():
    tmp_dir = tempfile.mkdtemp()
    repo = Repo.clone_from(GITHUB_REPO_URL, tmp_dir)
    repo.git.checkout('tesCFT')
    repo.git.checkout('-b', BRANCH_NAME)
    return repo, tmp_dir

# Git: Commit and push changes
def commit_and_push(repo):
    repo.git.add(all=True)
    repo.index.commit("Fix CloudFormation vulnerabilities using Azure OpenAI")
    origin = repo.remotes.origin
    origin.push(refspec=f"{BRANCH_NAME}:{BRANCH_NAME}")
    print(f"✅ Changes pushed to branch {BRANCH_NAME}")

# GitHub CLI to raise PR (needs `gh` installed and authenticated)
def raise_pr(repo_path):
    subprocess.run([
        "gh", "pr", "create",
        "--title", "Fix CloudFormation Vulnerabilities",
        "--body", "This PR contains fixes to detected vulnerabilities in CloudFormation templates.",
        "--base", "tesCFT",
        "--head", BRANCH_NAME
    ], cwd=repo_path)

def main():
    repo, repo_path = setup_repo()
    print(f"✅ Repo cloned to {repo_path}")

    cft_files = find_cft_files(repo_path)
    print(f"🔍 Found {len(cft_files)} CFT files.")

    changed = []

    for file_path in cft_files:
        print(f"🛠️  Processing: {file_path}")
        template = load_cft_file(file_path)
        if template is None:
            continue
        file_format = "json" if file_path.endswith(".json") else "yaml"
        fixed = scan_with_azure_openai(template,file_format)

        if save_fixed_template(file_path, fixed):
            changed.append(file_path)


    if changed:
        print(f"✅ Fixed {len(changed)} files. Committing changes...")
        commit_and_push(repo)
        raise_pr(repo_path)
    else:
        print("ℹ️ No valid files processed or changed.")

    # def handle_remove_readonly(func, path, exc_info):
    #     print(f"❌ Could not delete: {path}, retrying with chmod...")
    #     try:
    #         os.chmod(path, stat.S_IWRITE)
    #         func(path)
    #     except Exception as e:
    #         print(f"⚠️ Final delete failed for: {path}, reason: {e}")

    # shutil.rmtree(repo_path, onerror=handle_remove_readonly)

if __name__ == "__main__":
    main()
 