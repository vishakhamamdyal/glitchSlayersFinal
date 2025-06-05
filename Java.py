import os
import argparse
import json
from openai import AzureOpenAI

import logging
from typing import List, Dict

# from config import Config
import json
import time
from datetime import datetime
import subprocess

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class JavaCodeFixer:
    def __init__(self):
        # Initialize Azure OpenAI client
        # self.git = GitOperations()
        self.branch_name = f"security-fixes-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.client = AzureOpenAI(
            api_key=os.getenv("AZURE_OPENAI_KEY", "c093c3a427f04210967aed6d3f7e5ba3"),
            api_version="2023-12-01-preview",
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT", "https://bh-in-openai-glitchslayers.openai.azure.com/")
        )
        self.repo_path = os.getenv("REPO_PATH", "C:\\Users\\VMamdyal\\Downloads\\Employee-Payroll-Management-System-master\\Employee-Payroll-Management-System-master")
        # self.repo_path = os.getenv("REPO_PATH", "/c/Users/VMamdyal/Downloads/Employee-Payroll-Management-System-master")  # Default to current directory
        
        self.config = {
            "deployment_name": os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-35-turbo"),
            "temperature": 0.2,
            "max_tokens": 4000
        }
        self.results = []

    def run_git_command(self, command, cwd=None):
        """Helper function to run git commands in a specific directory"""
        try:
            result = subprocess.run(
                command,
                check=True,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd or self.repo_path  # Use the specified path or default to repo_path
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Git command failed: {e.stderr}")
            raise

    def setup_git_branch(self):
        """Create and checkout new branch for fixes"""
        print(f"\nCreating new branch: {self.branch_name}")
        self.run_git_command(f"git checkout -b {self.branch_name}")

    def git_commit_and_push(self):
        """Commit changes and push to remote"""
        print("\nCommitting changes...")
        self.run_git_command("git add .")
        commit_message = f"Security fixes applied by automated tool\n\nFixed {len([r for r in self.results if r['modified']])} vulnerabilities across {len(set(r['file'] for r in self.results if r['modified']))} files"
        self.run_git_command(f'git commit -m "{commit_message}"')
        print("\nPushing changes to remote...")
        self.run_git_command(f"git push origin {self.branch_name}")

    def create_pull_request(self):
        """Create a pull request using GitHub CLI"""
        print("\nCreating pull request...")
        pr_title = "Security Vulnerability Fixes"
        pr_body = "This PR contains automated security fixes for the following vulnerabilities:\n\n"
        
        # Add vulnerability details to PR body
        vuln_count = 1
        for result in self.results:
            if result["modified"]:
                pr_body += f"### {result['file']}\n"
                for vuln, explanation in zip(result["vulnerabilities_found"], result["explanations"]):
                    pr_body += f"{vuln_count}. **{vuln}**\n - {explanation}\n"
                    vuln_count += 1
                pr_body += "\n"
        
        try:
            # Using GitHub CLI to create PR
            pr_command = f'gh pr create --title "{pr_title}" --body "{pr_body}" --base main --head {self.branch_name}'
            pr_url = self.run_git_command(pr_command)
            print(f"\nPull request created: {pr_url}")
            return pr_url
        except Exception as e:
            print(f"\nWarning: Could not create pull request automatically. Please create it manually.")
            print(f"Branch pushed: {self.branch_name}")
            return None

    def find_java_files(self, root_dir):
        """Find all Java files in directory and subdirectories"""
        java_files = []
        for root, _, files in os.walk(root_dir):
            for file in files:
                if file.endswith(".java"):
                    java_files.append(os.path.join(root, file))
        return java_files

    def read_java_file(self, file_path):
        """Read Java code directly from file"""
        with open(file_path, "r") as file:
            return file.read()

    def generate_fixes(self, code_content, vulnerability_prompt):
        """Use Azure OpenAI to analyze and fix vulnerabilities"""
        system_prompt = """You are a senior Java security engineer. Analyze the provided Java code for 
        vulnerabilities and security issues. Provide fixed code with explanations of changes made.
        
        Required output format (JSON):
        {
            "original_code": "string",
            "vulnerabilities_found": ["list", "of", "vulnerabilities"],
            "fixed_code": "string",
            "explanations": ["list", "of", "explanations"]
        }"""

        user_prompt = f"""Vulnerability focus: {vulnerability_prompt}
        
        Java code to analyze:
        {code_content}"""

        response = self.client.chat.completions.create(
            model=self.config["deployment_name"],
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=self.config["temperature"],
            max_tokens=self.config["max_tokens"],
            response_format={"type": "json_object"}
        )

        return json.loads(response.choices[0].message.content)

    def update_file(self, file_path, fixed_code):
        """Update the original file with fixes"""
        with open(file_path, "w") as file:
            file.write(fixed_code)

    def process_file(self, file_path, vulnerability_prompt):
        """Complete processing pipeline for a Java file"""
        try:
            # Read original code
            original_code = self.read_java_file(file_path)
            
            # Generate fixes
            fixes = self.generate_fixes(original_code, vulnerability_prompt)
            
            # Only update if vulnerabilities were found
            if fixes["vulnerabilities_found"]:
                self.update_file(file_path, fixes["fixed_code"])
            
            result = {
                "file": file_path,
                "vulnerabilities_found": fixes["vulnerabilities_found"],
                "explanations": fixes["explanations"],
                "modified": bool(fixes["vulnerabilities_found"])
            }
            self.results.append(result)
            return result
        except Exception as e:
            print(f"Error processing {file_path}: {str(e)}")
            return None

    def process_directory(self, root_dir, vulnerability_prompt):
        """Process all Java files in a directory"""
        java_files = self.find_java_files(root_dir)
        print(f"Found {len(java_files)} Java files to analyze")
        
        for i, java_file in enumerate(java_files, 1):
            print(f"\nProcessing file {i}/{len(java_files)}: {java_file}")
            self.process_file(java_file, vulnerability_prompt)
        
        return self.results

    # def _apply_fixes(self):
    #     """Apply all fixes to the codebase"""
    #     # Create new branch
    #     branch_name = self.git.create_fix_branch()
    #     logger.info(f"Created new branch: {branch_name}")
        
    #     # Apply fixes
    #     changed_files = self.git.get_current_changes()
    #     logger.info(f"Applied fixes to {len(changed_files)} files: {', '.join(changed_files)}")
        
    #     # Push changes
    #     self.git.push_changes(branch_name)
    #     logger.info("Pushed changes to remote repository")
    #     self.git.create_pull_request(
    #                         title="Fix SonarQube Vulnerabilities",
    #                         body="This pull request fixes vulnerabilities identified by SonarQube."
    #                     )

def main():
    parser = argparse.ArgumentParser(description="Java Source Code Vulnerability Fixer using Azure OpenAI")
    parser.add_argument("root_dir", help="Root directory containing Java files (e.g., src/main/java)", 
                       default="src/main/java", nargs="?")
    parser.add_argument("--prompt", help="Specific vulnerability prompt", default="")
    parser.add_argument("--dry-run", help="Analyze only without modifying files", 
                       action="store_true")
    
    args = parser.parse_args()
    
    # Default vulnerability prompt if none provided
    default_prompt = """Check for common Java vulnerabilities including:
    1. SQL injection risks
    2. XSS vulnerabilities
    3. Insecure deserialization
    4. Hardcoded credentials
    5. Missing input validation
    6. Insecure random number generation
    7. Improper error handling
    8. Insecure file handling
    9. XXE vulnerabilities
    10. Security misconfigurations"""
    
    fixer = JavaCodeFixer()
    results = fixer.process_directory(args.root_dir, args.prompt or default_prompt)
    
    print("\n\n=== Summary Report ===")
    print(f"Processed {len(results)} files")
    
    modified_files = sum(1 for r in results if r["modified"])
    total_vulnerabilities = sum(len(r["vulnerabilities_found"]) for r in results if r["modified"])
    
    print(f"Files modified: {modified_files}")
    print(f"Total vulnerabilities fixed: {total_vulnerabilities}")
    
    if args.dry_run:
        print("\nDRY RUN: No files were actually modified")
    
    print("\nModified Files Details:")
    for result in results:
        if result["modified"]:
            print(f"\nFile: {result['file']}")
            print(f"Vulnerabilities fixed: {len(result['vulnerabilities_found'])}")
            for i, (vuln, explanation) in enumerate(zip(result["vulnerabilities_found"], result["explanations"]), 1):
                print(f" {i}. {vuln}")
                print(f" Explanation: {explanation}")


if __name__ == "__main__":
    main()
    ob = JavaCodeFixer()
    ob.setup_git_branch()
    ob.git_commit_and_push()
    ob.create_pull_request()