from androguard.misc import AnalyzeAPK

for apk_name in ["InsecureShop.apk", "evil_hijacker.apk"]:
    try:
        apk, d, dx = AnalyzeAPK(f"apks/{apk_name}")
        print(f"\n[{apk_name}]")
        print(f"  Package: {apk.get_package()}")
        schemes = []
        for activity in apk.get_activities():
            filters = apk.get_intent_filters("activity", activity)
            if filters:
                for item in filters.get("data", []):
                    if item.get("scheme") not in ["http", "https", None]:
                        schemes.append(item.get("scheme"))
        print(f"  Schemes: {schemes}")
    except Exception as e:
        print(f"  ERROR: {e}")
