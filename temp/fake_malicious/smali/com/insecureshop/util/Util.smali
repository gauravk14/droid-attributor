.class public final Lcom/insecureshop/util/Util;
.super Ljava/lang/Object;
.source "Util.kt"


# annotations
.annotation system Ldalvik/annotation/SourceDebugExtension;
    value = "SMAP\nUtil.kt\nKotlin\n*S Kotlin\n*F\n+ 1 Util.kt\ncom/insecureshop/util/Util\n*L\n1#1,70:1\n*E\n"
.end annotation

.annotation runtime Lkotlin/Metadata;
    bv = {
        0x1,
        0x0,
        0x3
    }
    d1 = {
        "\u0000F\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010 \n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\u0003\u0008\u00c6\u0002\u0018\u00002\u00020\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002J\u001e\u0010\u0003\u001a\u0012\u0012\u0004\u0012\u00020\u00050\u0004j\u0008\u0012\u0004\u0012\u00020\u0005`\u00062\u0006\u0010\u0007\u001a\u00020\u0008J\u0018\u0010\t\u001a\u0012\u0012\u0004\u0012\u00020\u00050\u0004j\u0008\u0012\u0004\u0012\u00020\u0005`\u0006H\u0002J\u0014\u0010\n\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u000b2\u0006\u0010\u0007\u001a\u00020\u0008J$\u0010\u000c\u001a\u001e\u0012\u0004\u0012\u00020\u000e\u0012\u0004\u0012\u00020\u000e0\rj\u000e\u0012\u0004\u0012\u00020\u000e\u0012\u0004\u0012\u00020\u000e`\u000fH\u0002J\u001e\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0007\u001a\u00020\u00082\u000e\u0008\u0002\u0010\u0012\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u000bJ\u0016\u0010\u0013\u001a\u00020\u00112\u0006\u0010\u0007\u001a\u00020\u00082\u0006\u0010\u0014\u001a\u00020\u0005J\u0016\u0010\u0015\u001a\u00020\u00162\u0006\u0010\u0017\u001a\u00020\u000e2\u0006\u0010\u0018\u001a\u00020\u000e\u00a8\u0006\u0019"
    }
    d2 = {
        "Lcom/insecureshop/util/Util;",
        "",
        "()V",
        "getCartProduct",
        "Ljava/util/ArrayList;",
        "Lcom/insecureshop/ProductDetail;",
        "Lkotlin/collections/ArrayList;",
        "context",
        "Landroid/content/Context;",
        "getProductList",
        "getProductsPrefs",
        "",
        "getUserCreds",
        "Ljava/util/HashMap;",
        "",
        "Lkotlin/collections/HashMap;",
        "saveProductList",
        "",
        "productList",
        "updateProductItem",
        "updateProductDetail",
        "verifyUserNamePassword",
        "",
        "username",
        "password",
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
.field public static final INSTANCE:Lcom/insecureshop/util/Util;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 10
    new-instance v0, Lcom/insecureshop/util/Util;

    invoke-direct {v0}, Lcom/insecureshop/util/Util;-><init>()V

    sput-object v0, Lcom/insecureshop/util/Util;->INSTANCE:Lcom/insecureshop/util/Util;

    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private final getProductList()Ljava/util/ArrayList;
    .locals 22
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Lcom/insecureshop/ProductDetail;",
            ">;"
        }
    .end annotation

    .line 28
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 29
    .local v0, "productList":Ljava/util/ArrayList;
    new-instance v11, Lcom/insecureshop/ProductDetail;

    const/4 v2, 0x1

    const-string v3, "Laptop"

    const-string v4, "https://images.pexels.com/photos/7974/pexels-photo.jpg"

    const-string v5, "80"

    const/4 v6, 0x1

    const-string v7, "https://www.insecureshopapp.com"

    const/4 v8, 0x0

    const/16 v9, 0x40

    const/4 v10, 0x0

    move-object v1, v11

    invoke-direct/range {v1 .. v10}, Lcom/insecureshop/ProductDetail;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;IILkotlin/jvm/internal/DefaultConstructorMarker;)V

    invoke-virtual {v0, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 30
    new-instance v1, Lcom/insecureshop/ProductDetail;

    const/4 v13, 0x2

    const-string v14, "Hat"

    const-string v15, "https://images.pexels.com/photos/984619/pexels-photo-984619.jpeg"

    const-string v16, "10"

    const/16 v17, 0x2

    const-string v18, "https://www.insecureshopapp.com"

    const/16 v19, 0x0

    const/16 v20, 0x40

    const/16 v21, 0x0

    move-object v12, v1

    invoke-direct/range {v12 .. v21}, Lcom/insecureshop/ProductDetail;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;IILkotlin/jvm/internal/DefaultConstructorMarker;)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 31
    new-instance v1, Lcom/insecureshop/ProductDetail;

    const/4 v3, 0x3

    const-string v4, "Sunglasses"

    const-string v5, "https://images.pexels.com/photos/343720/pexels-photo-343720.jpeg"

    const-string v6, "10"

    const/4 v7, 0x4

    const-string v8, "https://www.insecureshopapp.com"

    const/4 v9, 0x0

    const/16 v10, 0x40

    const/4 v11, 0x0

    move-object v2, v1

    invoke-direct/range {v2 .. v11}, Lcom/insecureshop/ProductDetail;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;IILkotlin/jvm/internal/DefaultConstructorMarker;)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 32
    new-instance v1, Lcom/insecureshop/ProductDetail;

    const/4 v13, 0x4

    const-string v14, "Watch"

    const-string v15, "https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg"

    const-string v16, "30"

    const/16 v17, 0x4

    const-string v18, "https://www.insecureshopapp.com"

    move-object v12, v1

    invoke-direct/range {v12 .. v21}, Lcom/insecureshop/ProductDetail;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;IILkotlin/jvm/internal/DefaultConstructorMarker;)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 33
    new-instance v1, Lcom/insecureshop/ProductDetail;

    const/4 v3, 0x5

    const-string v4, "Camera"

    const-string v5, "https://images.pexels.com/photos/225157/pexels-photo-225157.jpeg"

    const-string v6, "40"

    const/4 v7, 0x2

    const-string v8, "https://www.insecureshopapp.com"

    move-object v2, v1

    invoke-direct/range {v2 .. v11}, Lcom/insecureshop/ProductDetail;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;IILkotlin/jvm/internal/DefaultConstructorMarker;)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 34
    new-instance v1, Lcom/insecureshop/ProductDetail;

    const/4 v13, 0x6

    const-string v14, "Perfumes"

    const-string v15, "https://images.pexels.com/photos/264819/pexels-photo-264819.jpeg"

    const-string v16, "10"

    const/16 v17, 0x2

    const-string v18, "https://www.insecureshopapp.com"

    move-object v12, v1

    invoke-direct/range {v12 .. v21}, Lcom/insecureshop/ProductDetail;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;IILkotlin/jvm/internal/DefaultConstructorMarker;)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 35
    new-instance v1, Lcom/insecureshop/ProductDetail;

    const/4 v3, 0x7

    const-string v4, "Bagpack"

    const-string v5, "https://images.pexels.com/photos/532803/pexels-photo-532803.jpeg"

    const-string v6, "20"

    const-string v8, "https://www.insecureshopapp.com"

    move-object v2, v1

    invoke-direct/range {v2 .. v11}, Lcom/insecureshop/ProductDetail;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;IILkotlin/jvm/internal/DefaultConstructorMarker;)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 36
    new-instance v1, Lcom/insecureshop/ProductDetail;

    const/16 v13, 0x8

    const-string v14, "Jacket"

    const-string v15, "https://images.pexels.com/photos/789812/pexels-photo-789812.jpeg"

    const-string v16, "20"

    const-string v18, "https://www.insecureshopapp.com"

    move-object v12, v1

    invoke-direct/range {v12 .. v21}, Lcom/insecureshop/ProductDetail;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;IILkotlin/jvm/internal/DefaultConstructorMarker;)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 37
    return-object v0
.end method

.method private final getUserCreds()Ljava/util/HashMap;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/HashMap<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 13
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 14
    .local v0, "userCreds":Ljava/util/HashMap;
    move-object v1, v0

    check-cast v1, Ljava/util/Map;

    const-string v2, "shopuser"

    const-string v3, "!ns3csh0p"

    invoke-interface {v1, v2, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    return-object v0
.end method

.method public static synthetic saveProductList$default(Lcom/insecureshop/util/Util;Landroid/content/Context;Ljava/util/List;ILjava/lang/Object;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    .line 40
    invoke-direct {p0}, Lcom/insecureshop/util/Util;->getProductList()Ljava/util/ArrayList;

    move-result-object p2

    check-cast p2, Ljava/util/List;

    :cond_0
    invoke-virtual {p0, p1, p2}, Lcom/insecureshop/util/Util;->saveProductList(Landroid/content/Context;Ljava/util/List;)V

    return-void
.end method


# virtual methods
.method public final getCartProduct(Landroid/content/Context;)Ljava/util/ArrayList;
    .locals 5
    .param p1, "context"    # Landroid/content/Context;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            ")",
            "Ljava/util/ArrayList<",
            "Lcom/insecureshop/ProductDetail;",
            ">;"
        }
    .end annotation

    const-string v0, "context"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 62
    .local v0, "cartList":Ljava/util/ArrayList;
    invoke-virtual {p0, p1}, Lcom/insecureshop/util/Util;->getProductsPrefs(Landroid/content/Context;)Ljava/util/List;

    move-result-object v1

    .line 63
    .local v1, "productList":Ljava/util/List;
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lcom/insecureshop/ProductDetail;

    .line 64
    .local v3, "productDetail":Lcom/insecureshop/ProductDetail;
    invoke-virtual {v3}, Lcom/insecureshop/ProductDetail;->getQty()I

    move-result v4

    if-lez v4, :cond_0

    .line 65
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 63
    .end local v3    # "productDetail":Lcom/insecureshop/ProductDetail;
    :cond_0
    goto :goto_0

    .line 68
    :cond_1
    return-object v0
.end method

.method public final getProductsPrefs(Landroid/content/Context;)Ljava/util/List;
    .locals 3
    .param p1, "context"    # Landroid/content/Context;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            ")",
            "Ljava/util/List<",
            "Lcom/insecureshop/ProductDetail;",
            ">;"
        }
    .end annotation

    const-string v0, "context"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    sget-object v0, Lcom/insecureshop/util/Prefs;->INSTANCE:Lcom/insecureshop/util/Prefs;

    invoke-virtual {v0, p1}, Lcom/insecureshop/util/Prefs;->getInstance(Landroid/content/Context;)Lcom/insecureshop/util/Prefs;

    move-result-object v0

    invoke-virtual {v0}, Lcom/insecureshop/util/Prefs;->getProductList()Ljava/lang/String;

    move-result-object v0

    .line 47
    .local v0, "products":Ljava/lang/String;
    new-instance v1, Lcom/google/gson/Gson;

    invoke-direct {v1}, Lcom/google/gson/Gson;-><init>()V

    new-instance v2, Lcom/insecureshop/util/Util$getProductsPrefs$1;

    invoke-direct {v2}, Lcom/insecureshop/util/Util$getProductsPrefs$1;-><init>()V

    invoke-virtual {v2}, Lcom/insecureshop/util/Util$getProductsPrefs$1;->getType()Ljava/lang/reflect/Type;

    move-result-object v2

    invoke-virtual {v1, v0, v2}, Lcom/google/gson/Gson;->fromJson(Ljava/lang/String;Ljava/lang/reflect/Type;)Ljava/lang/Object;

    move-result-object v1

    const-string v2, "Gson().fromJson(products\u2026roductDetail>>() {}.type)"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Ljava/util/List;

    return-object v1
.end method

.method public final saveProductList(Landroid/content/Context;Ljava/util/List;)V
    .locals 2
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "productList"    # Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Ljava/util/List<",
            "Lcom/insecureshop/ProductDetail;",
            ">;)V"
        }
    .end annotation

    const-string v0, "context"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "productList"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    new-instance v0, Lcom/google/gson/Gson;

    invoke-direct {v0}, Lcom/google/gson/Gson;-><init>()V

    invoke-virtual {v0, p2}, Lcom/google/gson/Gson;->toJson(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    .line 42
    .local v0, "productJson":Ljava/lang/String;
    sget-object v1, Lcom/insecureshop/util/Prefs;->INSTANCE:Lcom/insecureshop/util/Prefs;

    invoke-virtual {v1, p1}, Lcom/insecureshop/util/Prefs;->getInstance(Landroid/content/Context;)Lcom/insecureshop/util/Prefs;

    move-result-object v1

    invoke-virtual {v1, v0}, Lcom/insecureshop/util/Prefs;->setProductList(Ljava/lang/String;)V

    .line 43
    return-void
.end method

.method public final updateProductItem(Landroid/content/Context;Lcom/insecureshop/ProductDetail;)V
    .locals 5
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "updateProductDetail"    # Lcom/insecureshop/ProductDetail;

    const-string v0, "context"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "updateProductDetail"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    invoke-virtual {p0, p1}, Lcom/insecureshop/util/Util;->getProductsPrefs(Landroid/content/Context;)Ljava/util/List;

    move-result-object v0

    .line 52
    .local v0, "productList":Ljava/util/List;
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lcom/insecureshop/ProductDetail;

    .line 53
    .local v2, "productDetail":Lcom/insecureshop/ProductDetail;
    invoke-virtual {v2}, Lcom/insecureshop/ProductDetail;->getId()I

    move-result v3

    invoke-virtual {p2}, Lcom/insecureshop/ProductDetail;->getId()I

    move-result v4

    if-ne v3, v4, :cond_0

    .line 54
    invoke-virtual {p2}, Lcom/insecureshop/ProductDetail;->getQty()I

    move-result v3

    invoke-virtual {v2, v3}, Lcom/insecureshop/ProductDetail;->setQty(I)V

    .line 52
    .end local v2    # "productDetail":Lcom/insecureshop/ProductDetail;
    :cond_0
    goto :goto_0

    .line 57
    :cond_1
    invoke-virtual {p0, p1, v0}, Lcom/insecureshop/util/Util;->saveProductList(Landroid/content/Context;Ljava/util/List;)V

    .line 58
    return-void
.end method

.method public final verifyUserNamePassword(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 4
    .param p1, "username"    # Ljava/lang/String;
    .param p2, "password"    # Ljava/lang/String;

    const-string v0, "username"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "password"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    invoke-direct {p0}, Lcom/insecureshop/util/Util;->getUserCreds()Ljava/util/HashMap;

    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    .line 20
    invoke-direct {p0}, Lcom/insecureshop/util/Util;->getUserCreds()Ljava/util/HashMap;

    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    .line 21
    .local v0, "passwordValue":Ljava/lang/String;
    const/4 v2, 0x2

    const/4 v3, 0x0

    invoke-static {v0, p2, v1, v2, v3}, Lkotlin/text/StringsKt;->equals$default(Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Z

    move-result v1

    return v1

    .line 23
    .end local v0    # "passwordValue":Ljava/lang/String;
    :cond_0
    return v1
.end method
