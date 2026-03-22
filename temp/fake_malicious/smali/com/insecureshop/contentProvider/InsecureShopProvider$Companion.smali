.class public final Lcom/insecureshop/contentProvider/InsecureShopProvider$Companion;
.super Ljava/lang/Object;
.source "InsecureShopProvider.kt"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/insecureshop/contentProvider/InsecureShopProvider;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    bv = {
        0x1,
        0x0,
        0x3
    }
    d1 = {
        "\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0086T\u00a2\u0006\u0002\n\u0000R\u001c\u0010\u0005\u001a\u0004\u0018\u00010\u0006X\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0007\u0010\u0008\"\u0004\u0008\t\u0010\n\u00a8\u0006\u000b"
    }
    d2 = {
        "Lcom/insecureshop/contentProvider/InsecureShopProvider$Companion;",
        "",
        "()V",
        "URI_CODE",
        "",
        "uriMatcher",
        "Landroid/content/UriMatcher;",
        "getUriMatcher",
        "()Landroid/content/UriMatcher;",
        "setUriMatcher",
        "(Landroid/content/UriMatcher;)V",
        "app_debug"
    }
    k = 0x1
    mv = {
        0x1,
        0x1,
        0x10
    }
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/DefaultConstructorMarker;)V
    .locals 0
    .param p1, "$constructor_marker"    # Lkotlin/jvm/internal/DefaultConstructorMarker;

    .line 14
    invoke-direct {p0}, Lcom/insecureshop/contentProvider/InsecureShopProvider$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final getUriMatcher()Landroid/content/UriMatcher;
    .locals 1

    .line 15
    invoke-static {}, Lcom/insecureshop/contentProvider/InsecureShopProvider;->access$getUriMatcher$cp()Landroid/content/UriMatcher;

    move-result-object v0

    return-object v0
.end method

.method public final setUriMatcher(Landroid/content/UriMatcher;)V
    .locals 0
    .param p1, "<set-?>"    # Landroid/content/UriMatcher;

    .line 15
    invoke-static {p1}, Lcom/insecureshop/contentProvider/InsecureShopProvider;->access$setUriMatcher$cp(Landroid/content/UriMatcher;)V

    return-void
.end method
