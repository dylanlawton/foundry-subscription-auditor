from az_reader import list_resource_groups
import os
from dotenv import load_dotenv

load_dotenv()

if __name__ == "__main__":
    sub_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    print(f"Checking resource groups in subscription: {sub_id}")
    rg_list = list_resource_groups(sub_id)
    print("\nFound Resource Groups:")
    for rg in rg_list:
        print(f"- {rg}")
