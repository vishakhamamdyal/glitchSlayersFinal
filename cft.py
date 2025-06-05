import os
import json
import yaml
import subprocess
import tempfile
import shutil
import stat
import re
import argparse
from datetime import datetime
from openai import AzureOpenAI
from git import Repo

# Azure OpenAI Setup
endpoint = "https://bh-in-openai-glitchslayers.openai.azure.com/"
subscription_key = "c093c3a427f04210967aed6d3f7e5ba3"
api_version = "2024-12-01-preview"
deployment = "gpt-35-turbo"

client = AzureOpenAI(
    api_version=api_version,
    azure_endpoint=endpoint,
    api_key=subscription_key,
)

# --- Java Vulnerability Fixer ---
class JavaCodeFixer:
    def __init__(self):
        self.branch_name = f"java-security-fixes-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.client = client
        self.repo_path = os.getenv("JAVA_REPO_PATH", ".")
        self.config = {
            "deployment_name": deployment,
            "temperature": 0.2,
            "max_tokens": 4000
        }
        self.results = []

    def run_git_command(self, command, cwd=None):
        return subprocess.run(
            command, shell=True, check=True, cwd=cwd or self.repo_path,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        ).stdout.strip()

    def setup_git_branch(self):
        self.run_git_command(f"git checkout -b {self.branch_name}")

    def git_commit_and_push(self):
        self.run_git_command("git add .")
        commit_message = f"Java Security Fixes via Azure OpenAI"
        self.run_git_command(f'git commit -m "{commit_message}"')
        self.run_git_command(f"git push origin {self.branch_name}")

    def create_pull_request(self):
        subprocess.run([
            "gh", "pr", "create",
            "--title", "Fix Java Vulnerabilities",
            "--body", "Automated PR to fix Java vulnerabilities using Azure OpenAI.",
            "--base", "main",
            "--head", self.branch_name
        ], cwd=self.repo_path)

    def find_java_files(self, root_dir):
        return [os.path.join(root, file)
                for root, _, files in os.walk(root_dir)
                for file in files if file.endswith(".java")]

    def generate_fixes(self, code_content, vulnerability_prompt):
        prompt = (
            "You are a senior Java security engineer. Return JSON in the following format:\n"
            "{'original_code': '', 'vulnerabilities_found': [], 'fixed_code': '', 'explanations': []}"
        )
        user_prompt = f"Focus: {vulnerability_prompt}\nCode:\n{code_content}"
        response = self.client.chat.completions.create(
            model=self.config["deployment_name"],
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=self.config["temperature"],
            max_tokens=self.config["max_tokens"],
            response_format={"type": "json_object"}
        )
        return json.loads(response.choices[0].message.content)

    def update_file(self, path, fixed_code):
        with open(path, "w") as f:
            f.write(fixed_code)

    def process_directory(self, root_dir, vulnerability_prompt):
        java_files = self.find_java_files(root_dir)
        for file_path in java_files:
            with open(file_path, "r") as f:
                code = f.read()
            fixes = self.generate_fixes(code, vulnerability_prompt)
            if fixes["vulnerabilities_found"]:
                self.update_file(file_path, fixes["fixed_code"])
                self.results.append({
                    "file": file_path,
                    "vulnerabilities_found": fixes["vulnerabilities_found"],
                    "explanations": fixes["explanations"],
                    "modified": True
                })


# --- CloudFormation Fixer ---
def register_cfn_tags():
    def tag_scalar(tag):
        return lambda loader, node: {tag: loader.construct_scalar(node)}
    def tag_sequence(tag):
        return lambda loader, node: {tag: loader.construct_sequence(node)}
    def tag_mapping(tag):
        return lambda loader, node: {tag: loader.construct_mapping(node)}
    tags = {
        '!Ref': 'Ref', '!GetAtt': 'Fn::GetAtt', '!Sub': 'Fn::Sub', '!Join': 'Fn::Join',
        '!Select': 'Fn::Select', '!Split': 'Fn::Split', '!Equals': 'Fn::Equals',
        '!If': 'Fn::If', '!Not': 'Fn::Not', '!And': 'Fn::And', '!Or': 'Fn::Or',
        '!FindInMap': 'Fn::FindInMap', '!ImportValue': 'Fn::ImportValue',
        '!Base64': 'Fn::Base64', '!Cidr': 'Fn::Cidr', '!Transform': 'Fn::Transform'
    }
    for tag, mapped in tags.items():
        loader_func = (
            tag_sequence(mapped) if tag in ['!Join', '!Split', '!Select', '!Equals', '!If', '!Not', '!And', '!Or', '!FindInMap', '!Cidr']
            else tag_mapping(mapped) if tag == '!Transform'
            else tag_scalar(mapped)
        )
        yaml.add_constructor(tag, loader_func, Loader=yaml.SafeLoader)

register_cfn_tags()

def scan_with_openai(template_dict, file_format):
    best_practices = (
        "- Avoid wildcards in IAM\n"
        "- Don’t expose 0.0.0.0/0\n"
        "- Enable encryption\n"
        "- Avoid hardcoded values\n"
        "- Enable logging"
    )
    prompt = (
        f"Fix this CloudFormation template based on best practices:\n{best_practices}\n"
        f"Return valid {file_format.upper()} only:\n\n"
        f"{json.dumps(template_dict) if file_format == 'json' else yaml.safe_dump(template_dict)}"
    )
    response = client.chat.completions.create(
        messages=[
            {"role": "system", "content": "You are a CloudFormation fixer."},
            {"role": "user", "content": prompt}
        ],
        model=deployment,
        max_tokens=4096,
        temperature=0.3
    )
    fixed = response.choices[0].message.content
    return re.sub(r"^```yaml\s*|```$", "", fixed.strip(), flags=re.MULTILINE)

def find_cft_files(repo_dir):
    return [os.path.join(root, file)
            for root, _, files in os.walk(repo_dir)
            for file in files if file.endswith((".yaml", ".yml", ".json"))]

def load_cft_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f) if path.endswith(".json") else yaml.load(f, Loader=yaml.SafeLoader)
    except Exception as e:
        print(f"❌ Failed to read {path}: {e}")
        return None

def save_fixed_template(path, content):
    try:
        with open(path, "w", encoding="utf-8") as f:
            if path.endswith(".json"):
                json.dump(json.loads(content), f, indent=2)
            else:
                yaml.safe_dump(yaml.safe_load(content), f)
    except Exception as e:
        print(f"❌ Failed to save fixed template: {e}")

def process_cft_repo():
    repo_url = "https://github.com/vishakhamamdyal/glitchSlayers.git"
    branch = f"cft-vulnerabilities-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    repo_dir = tempfile.mkdtemp()
    repo = Repo.clone_from(repo_url, repo_dir)
    repo.git.checkout("tesCFT")
    repo.git.checkout("-b", branch)

    changed_files = []
    for path in find_cft_files(repo_dir):
        template = load_cft_file(path)
        if not template: continue
        file_format = "json" if path.endswith(".json") else "yaml"
        fixed = scan_with_openai(template, file_format)
        save_fixed_template(path, fixed)
        changed_files.append(path)

    if changed_files:
        repo.git.add(all=True)
        repo.index.commit("Fix CFT vulnerabilities using Azure OpenAI")
        repo.remotes.origin.push(refspec=f"{branch}:{branch}")
        subprocess.run([
            "gh", "pr", "create",
            "--title", "Fix CFT Vulnerabilities",
            "--body", "Fixed CloudFormation vulnerabilities.",
            "--base", "tesCFT",
            "--head", branch
        ], cwd=repo_dir)

# --- Master Main Function ---
def main():

    # Run CFT Fixing
    print("\n🔍 Fixing CloudFormation templates...")
    process_cft_repo()
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--java", help="Java code path", default=".")
    parser.add_argument("--prompt", help="Java vulnerability prompt", default="Check common Java issues")
    args = parser.parse_args()

    # Run Java Fixing
    print("🔍 Fixing Java vulnerabilities...")
    java_fixer = JavaCodeFixer()
    java_fixer.process_directory(args.java, args.prompt)
    if any(r["modified"] for r in java_fixer.results):
        java_fixer.setup_git_branch()
        java_fixer.git_commit_and_push()
        java_fixer.create_pull_request()
    else:
        print("✅ No Java vulnerabilities found.")

if __name__ == "__main__":
    main()
