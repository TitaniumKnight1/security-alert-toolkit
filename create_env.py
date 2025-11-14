import os

# --- Configuration ---
ENV_FILE_NAME = ".env"
API_KEYS_TO_SET = {
    "VIRUSTOTAL_API_KEY": "VirusTotal API Key",
    "ABUSEIPDB_API_KEY": "AbuseIPDB API Key",
    "GEMINI_API_KEY": "Gemini API Key",
    # Add more keys here if needed in the future
    # "ANOTHER_API_KEY": "Description for Another Key",
}
# --- End Configuration ---

def create_env_file():
    """
    Prompts the user for API keys and creates a .env file.
    Warns if the file already exists.
    """
    env_file_path = os.path.join(os.path.dirname(__file__), ENV_FILE_NAME)
    env_values = {}
    proceed = True

    if os.path.exists(env_file_path):
        print(f"⚠️ Warning: Configuration file '{ENV_FILE_NAME}' already exists.")
        overwrite = input("Do you want to overwrite it? (yes/no): ").lower().strip()
        if overwrite != 'yes':
            print("Skipping file creation.")
            proceed = False

    if proceed:
        print(f"\nEnter the required API keys (leave blank to skip a key):")
        for var_name, description in API_KEYS_TO_SET.items():
            value = input(f"- {description} ({var_name}): ").strip()
            if value: # Only store non-empty values
                env_values[var_name] = value
            else:
                print(f"  (Skipping {var_name})")

        if not env_values:
            print("\nNo API keys were entered. No .env file created.")
            return

        try:
            with open(env_file_path, 'w') as f:
                f.write("# API Keys for Phishing Analyzer Script\n")
                f.write("# This file should NOT be committed to Git.\n\n")
                for var_name, value in env_values.items():
                    # Basic quoting for values with spaces, though usually not needed for API keys
                    if ' ' in value or '#' in value:
                         f.write(f'{var_name}="{value}"\n')
                    else:
                         f.write(f'{var_name}={value}\n')

            print(f"\n✅ Successfully created/updated '{ENV_FILE_NAME}' with the provided keys.")
            print("🔒 IMPORTANT: Make sure to add '.env' to your .gitignore file!")

        except IOError as e:
            print(f"\n❌ Error writing to file '{env_file_path}': {e}")

if __name__ == "__main__":
    create_env_file()
    input("\nPress Enter to exit.")