"""Developer environment verification script."""

import os
import shutil
import sys


def check_tool(tool: str) -> bool:
    path = shutil.which(tool)
    status = "FOUND" if path else "NOT FOUND"
    print(f"Checking {tool:15} ... {status}")
    return bool(path)


def main() -> None:
    print("=== CyberDuel AI Environment Verification ===\n")
    print(f"Python Version: {sys.version}")

    tools = ["uv", "docker", "git"]
    all_ok = all(check_tool(t) for t in tools)

    env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_file):
        print("\nNote: .env file does not exist. Creating from .env.example...")
        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), "..", ".env.example"),
            env_file,
        )
        print("Created .env successfully.")

    if all_ok:
        print("\nEnvironment is ready for development.")
    else:
        print("\nSome tools are missing. Review output above.")


if __name__ == "__main__":
    main()
