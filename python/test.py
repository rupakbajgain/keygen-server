from mfs import KeyserverClient, Ok, Archive, Key, Error, Data

def main():
    with KeyserverClient() as client:

        # Test Ping
        res = client.ping()
        if isinstance(res, Ok):
            print(f"✅ Success: {res.msg}")
        elif isinstance(res, Error):
            print(f"❌ Server Error: {res.msg}")

        # Test Unlock
        res = client.unlock("secret_pass")
        if isinstance(res, Error):
            print(f"❌ Failed to unlock: {res.msg}")
        else:
            print("🔓 KeyServer Unlocked")

        # Test Archive Generation
        res = client.archive_generate()
        if isinstance(res, Archive):
            print(f"📦 Archive Created. ID: {res.archive_id.hex()}")

            # Use the object directly to reload
            load_res = client.archive_load(res)
            print(f"🔄 Reload Response Type: {type(load_res).__name__}")
            print(load_res)

if __name__ == "__main__":
    main()
