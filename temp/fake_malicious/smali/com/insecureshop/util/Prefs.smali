.class public final Lcom/insecureshop/util/Prefs;
.super Ljava/lang/Object;
.source "Prefs.kt"


# annotations
.annotation runtime Lkotlin/Metadata;
    bv = {
        0x1,
        0x0,
        0x3
    }
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0011\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0010\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u00c6\u0002\u0018\u00002\u00020\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002J\u0006\u0010\u001e\u001a\u00020\u001fJ\u000e\u0010 \u001a\u00020\u00002\u0006\u0010!\u001a\u00020\"R(\u0010\u0005\u001a\u0004\u0018\u00010\u00042\u0008\u0010\u0003\u001a\u0004\u0018\u00010\u00048F@FX\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008\u0006\u0010\u0007\"\u0004\u0008\u0008\u0010\tR(\u0010\n\u001a\u0004\u0018\u00010\u00042\u0008\u0010\u0003\u001a\u0004\u0018\u00010\u00048F@FX\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008\u000b\u0010\u0007\"\u0004\u0008\u000c\u0010\tR\u001c\u0010\r\u001a\u0004\u0018\u00010\u0000X\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u000e\u0010\u000f\"\u0004\u0008\u0010\u0010\u0011R(\u0010\u0012\u001a\u0004\u0018\u00010\u00042\u0008\u0010\u0003\u001a\u0004\u0018\u00010\u00048F@FX\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008\u0013\u0010\u0007\"\u0004\u0008\u0014\u0010\tR\u001a\u0010\u0015\u001a\u00020\u0016X\u0086.\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0017\u0010\u0018\"\u0004\u0008\u0019\u0010\u001aR(\u0010\u001b\u001a\u0004\u0018\u00010\u00042\u0008\u0010\u0003\u001a\u0004\u0018\u00010\u00048F@FX\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008\u001c\u0010\u0007\"\u0004\u0008\u001d\u0010\t\u00a8\u0006#"
    }
    d2 = {
        "Lcom/insecureshop/util/Prefs;",
        "",
        "()V",
        "value",
        "",
        "data",
        "getData",
        "()Ljava/lang/String;",
        "setData",
        "(Ljava/lang/String;)V",
        "password",
        "getPassword",
        "setPassword",
        "prefs",
        "getPrefs",
        "()Lcom/insecureshop/util/Prefs;",
        "setPrefs",
        "(Lcom/insecureshop/util/Prefs;)V",
        "productList",
        "getProductList",
        "setProductList",
        "sharedpreferences",
        "Landroid/content/SharedPreferences;",
        "getSharedpreferences",
        "()Landroid/content/SharedPreferences;",
        "setSharedpreferences",
        "(Landroid/content/SharedPreferences;)V",
        "username",
        "getUsername",
        "setUsername",
        "clearAll",
        "",
        "getInstance",
        "context",
        "Landroid/content/Context;",
        "app_debug"
    }
    k = 0x1
    mv = {
        0x1,
        0x1,
        0x10
    }
.end annotation


# static fields
.field public static final INSTANCE:Lcom/insecureshop/util/Prefs;

.field private static prefs:Lcom/insecureshop/util/Prefs;

.field public static sharedpreferences:Landroid/content/SharedPreferences;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 6
    new-instance v0, Lcom/insecureshop/util/Prefs;

    invoke-direct {v0}, Lcom/insecureshop/util/Prefs;-><init>()V

    sput-object v0, Lcom/insecureshop/util/Prefs;->INSTANCE:Lcom/insecureshop/util/Prefs;

    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final clearAll()V
    .locals 2

    .line 46
    sget-object v0, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    if-nez v0, :cond_0

    const-string v1, "sharedpreferences"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->clear()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 47
    return-void
.end method

.method public final getData()Ljava/lang/String;
    .locals 3

    .line 21
    sget-object v0, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    if-nez v0, :cond_0

    const-string v1, "sharedpreferences"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    const-string v1, "data"

    const-string v2, ""

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getInstance(Landroid/content/Context;)Lcom/insecureshop/util/Prefs;
    .locals 2
    .param p1, "context"    # Landroid/content/Context;

    const-string v0, "context"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    sget-object v0, Lcom/insecureshop/util/Prefs;->prefs:Lcom/insecureshop/util/Prefs;

    if-nez v0, :cond_0

    .line 13
    nop

    .line 14
    const/4 v0, 0x0

    const-string v1, "Prefs"

    invoke-virtual {p1, v1, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    const-string v1, "context.getSharedPrefere\u2026s\", Context.MODE_PRIVATE)"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    sput-object v0, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    .line 15
    move-object v0, p0

    check-cast v0, Lcom/insecureshop/util/Prefs;

    sput-object v0, Lcom/insecureshop/util/Prefs;->prefs:Lcom/insecureshop/util/Prefs;

    .line 17
    :cond_0
    sget-object v0, Lcom/insecureshop/util/Prefs;->prefs:Lcom/insecureshop/util/Prefs;

    if-nez v0, :cond_1

    invoke-static {}, Lkotlin/jvm/internal/Intrinsics;->throwNpe()V

    :cond_1
    return-object v0
.end method

.method public final getPassword()Ljava/lang/String;
    .locals 3

    .line 33
    sget-object v0, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    if-nez v0, :cond_0

    const-string v1, "sharedpreferences"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    const-string v1, "password"

    const-string v2, ""

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getPrefs()Lcom/insecureshop/util/Prefs;
    .locals 1

    .line 9
    sget-object v0, Lcom/insecureshop/util/Prefs;->prefs:Lcom/insecureshop/util/Prefs;

    return-object v0
.end method

.method public final getProductList()Ljava/lang/String;
    .locals 3

    .line 39
    sget-object v0, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    if-nez v0, :cond_0

    const-string v1, "sharedpreferences"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    const-string v1, "productList"

    const-string v2, ""

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getSharedpreferences()Landroid/content/SharedPreferences;
    .locals 2

    .line 8
    sget-object v0, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    if-nez v0, :cond_0

    const-string v1, "sharedpreferences"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    return-object v0
.end method

.method public final getUsername()Ljava/lang/String;
    .locals 3

    .line 27
    sget-object v0, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    if-nez v0, :cond_0

    const-string v1, "sharedpreferences"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    const-string v1, "username"

    const-string v2, ""

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final setData(Ljava/lang/String;)V
    .locals 2
    .param p1, "value"    # Ljava/lang/String;

    .line 23
    sget-object v0, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    if-nez v0, :cond_0

    const-string v1, "sharedpreferences"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    const-string v1, "data"

    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 24
    return-void
.end method

.method public final setPassword(Ljava/lang/String;)V
    .locals 2
    .param p1, "value"    # Ljava/lang/String;

    .line 35
    sget-object v0, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    if-nez v0, :cond_0

    const-string v1, "sharedpreferences"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    const-string v1, "password"

    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 36
    return-void
.end method

.method public final setPrefs(Lcom/insecureshop/util/Prefs;)V
    .locals 0
    .param p1, "<set-?>"    # Lcom/insecureshop/util/Prefs;

    .line 9
    sput-object p1, Lcom/insecureshop/util/Prefs;->prefs:Lcom/insecureshop/util/Prefs;

    return-void
.end method

.method public final setProductList(Ljava/lang/String;)V
    .locals 2
    .param p1, "value"    # Ljava/lang/String;

    .line 41
    sget-object v0, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    if-nez v0, :cond_0

    const-string v1, "sharedpreferences"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    const-string v1, "productList"

    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 42
    return-void
.end method

.method public final setSharedpreferences(Landroid/content/SharedPreferences;)V
    .locals 1
    .param p1, "<set-?>"    # Landroid/content/SharedPreferences;

    const-string v0, "<set-?>"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    sput-object p1, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    return-void
.end method

.method public final setUsername(Ljava/lang/String;)V
    .locals 2
    .param p1, "value"    # Ljava/lang/String;

    .line 29
    sget-object v0, Lcom/insecureshop/util/Prefs;->sharedpreferences:Landroid/content/SharedPreferences;

    if-nez v0, :cond_0

    const-string v1, "sharedpreferences"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    const-string v1, "username"

    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 30
    return-void
.end method
