import wget
import os
import argparse
import re

def run_templates(domain):
    if not os.path.exists("all.txt"):
        print("Error: all.txt not found")
        return

    safe_domain = re.sub(r'[^\w\-.]', '_', domain)
    domain_dir = os.path.join("results", safe_domain)
    os.makedirs(domain_dir, exist_ok=True)

    findings_file = os.path.join(domain_dir, "findings.txt")

    with open("all.txt", "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            url = "https://amad3us47.github.io/data/" + line
            try:
                wget.download(url)
                print(f"\nUsing {line} template")

                safe_name = line.replace("/", "_").replace("\\", "_")
                resp_dir  = os.path.join(domain_dir, safe_name)
                os.makedirs(resp_dir, exist_ok=True)

                os.system(
                    f'nuclei -u {domain} -t "{line}" '
                    f'-sresp -srd "{resp_dir}" '
                    f'-o "{findings_file}" '   # only matched findings saved here
                    f'-irr'                    # include req/resp in findings
                )

                print(f"Req/Resp → {resp_dir}/")

            except Exception as e:
                print(f"\nFailed to download {line}: {e}")
                continue
            finally:
                file_path = os.path.join(os.getcwd(), line)
                if os.path.exists(file_path):
                    os.remove(file_path)

    print(f"\nScan complete.")
    print(f"All findings → {findings_file}")
    print(f"Raw req/resp → {domain_dir}/<template>/")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", required=True)
    args = parser.parse_args()
    run_templates(args.domain)

if __name__ == "__main__":
    main()
