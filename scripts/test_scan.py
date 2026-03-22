from androguard.misc import AnalyzeAPK

# Load the APK
print("[*] Loading APK...")
apk, d, dx = AnalyzeAPK("apks/InsecureShop.apk")

# Basic info
print("\n=== APK INFO ===")
print(f"Package Name : {apk.get_package()}")
print(f"App Name     : {apk.get_app_name()}")
print(f"Version      : {apk.get_androidversion_name()}")
print(f"Min SDK      : {apk.get_min_sdk_version()}")
print(f"Target SDK   : {apk.get_target_sdk_version()}")

# Permissions
print("\n=== PERMISSIONS ===")
for perm in apk.get_permissions():
    print(f"  {perm}")

# Intent filters (the core of your project!)
print("\n=== INTENT FILTERS (Deep Links) ===")
for activity in apk.get_activities():
    filters = apk.get_intent_filters("activity", activity)
    if filters:
        print(f"\n  Activity: {activity}")
        for key, values in filters.items():
            print(f"    {key}: {values}")
