.class public final Lcom/insecureshop/ProductListActivity;
.super Landroidx/appcompat/app/AppCompatActivity;
.source "ProductListActivity.kt"


# annotations
.annotation runtime Lkotlin/Metadata;
    bv = {
        0x1,
        0x0,
        0x3
    }
    d1 = {
        "\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0005\u00a2\u0006\u0002\u0010\u0002J\u0012\u0010\u0005\u001a\u00020\u00062\u0008\u0010\u0007\u001a\u0004\u0018\u00010\u0008H\u0014J\u0012\u0010\t\u001a\u00020\n2\u0008\u0010\u000b\u001a\u0004\u0018\u00010\u000cH\u0016J\u0010\u0010\r\u001a\u00020\n2\u0006\u0010\u000e\u001a\u00020\u000fH\u0016R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0010"
    }
    d2 = {
        "Lcom/insecureshop/ProductListActivity;",
        "Landroidx/appcompat/app/AppCompatActivity;",
        "()V",
        "productDetailBroadCast",
        "Lcom/insecureshop/broadcast/ProductDetailBroadCast;",
        "onCreate",
        "",
        "savedInstanceState",
        "Landroid/os/Bundle;",
        "onCreateOptionsMenu",
        "",
        "menu",
        "Landroid/view/Menu;",
        "onOptionsItemSelected",
        "item",
        "Landroid/view/MenuItem;",
        "app_debug"
    }
    k = 0x1
    mv = {
        0x1,
        0x1,
        0x10
    }
.end annotation


# instance fields
.field private _$_findViewCache:Ljava/util/HashMap;

.field private final productDetailBroadCast:Lcom/insecureshop/broadcast/ProductDetailBroadCast;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 17
    invoke-direct {p0}, Landroidx/appcompat/app/AppCompatActivity;-><init>()V

    .line 18
    new-instance v0, Lcom/insecureshop/broadcast/ProductDetailBroadCast;

    invoke-direct {v0}, Lcom/insecureshop/broadcast/ProductDetailBroadCast;-><init>()V

    iput-object v0, p0, Lcom/insecureshop/ProductListActivity;->productDetailBroadCast:Lcom/insecureshop/broadcast/ProductDetailBroadCast;

    return-void
.end method


# virtual methods
.method public _$_clearFindViewByIdCache()V
    .locals 1

    iget-object v0, p0, Lcom/insecureshop/ProductListActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    :cond_0
    return-void
.end method

.method public _$_findCachedViewById(I)Landroid/view/View;
    .locals 2

    iget-object v0, p0, Lcom/insecureshop/ProductListActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-nez v0, :cond_0

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lcom/insecureshop/ProductListActivity;->_$_findViewCache:Ljava/util/HashMap;

    :cond_0
    iget-object v0, p0, Lcom/insecureshop/ProductListActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    if-nez v0, :cond_1

    invoke-virtual {p0, p1}, Landroidx/fragment/app/FragmentActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    iget-object v1, p0, Lcom/insecureshop/ProductListActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {v1, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    return-object v0
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 7
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .line 20
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V

    .line 21
    sget-object v0, Lcom/insecureshop/util/Prefs;->INSTANCE:Lcom/insecureshop/util/Prefs;

    invoke-virtual {p0}, Lcom/insecureshop/ProductListActivity;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    const-string v2, "applicationContext"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Lcom/insecureshop/util/Prefs;->getInstance(Landroid/content/Context;)Lcom/insecureshop/util/Prefs;

    move-result-object v0

    invoke-virtual {v0}, Lcom/insecureshop/util/Prefs;->getUsername()Ljava/lang/String;

    move-result-object v0

    check-cast v0, Ljava/lang/CharSequence;

    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 22
    new-instance v0, Landroid/content/Intent;

    move-object v1, p0

    check-cast v1, Landroid/content/Context;

    const-class v2, Lcom/insecureshop/LoginActivity;

    invoke-direct {v0, v1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 23
    .local v0, "intent":Landroid/content/Intent;
    invoke-virtual {p0, v0}, Lcom/insecureshop/ProductListActivity;->startActivity(Landroid/content/Intent;)V

    .line 24
    invoke-virtual {p0}, Lcom/insecureshop/ProductListActivity;->finish()V

    .line 25
    return-void

    .line 27
    .end local v0    # "intent":Landroid/content/Intent;
    :cond_0
    const v0, 0x7f0c0023

    invoke-virtual {p0, v0}, Lcom/insecureshop/ProductListActivity;->setContentView(I)V

    .line 28
    sget v0, Lcom/insecureshop/R$id;->toolbar:I

    invoke-virtual {p0, v0}, Lcom/insecureshop/ProductListActivity;->_$_findCachedViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p0, v0}, Lcom/insecureshop/ProductListActivity;->setSupportActionBar(Landroidx/appcompat/widget/Toolbar;)V

    .line 30
    new-instance v0, Landroid/content/IntentFilter;

    const-string v1, "com.insecureshop.action.PRODUCT_DETAIL"

    invoke-direct {v0, v1}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 31
    .local v0, "intentFilter":Landroid/content/IntentFilter;
    iget-object v1, p0, Lcom/insecureshop/ProductListActivity;->productDetailBroadCast:Lcom/insecureshop/broadcast/ProductDetailBroadCast;

    check-cast v1, Landroid/content/BroadcastReceiver;

    invoke-virtual {p0, v1, v0}, Lcom/insecureshop/ProductListActivity;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 32
    new-instance v1, Lcom/insecureshop/ProductAdapter;

    invoke-direct {v1}, Lcom/insecureshop/ProductAdapter;-><init>()V

    .line 33
    .local v1, "productAdapter":Lcom/insecureshop/ProductAdapter;
    sget v2, Lcom/insecureshop/R$id;->recyclerview:I

    invoke-virtual {p0, v2}, Lcom/insecureshop/ProductListActivity;->_$_findCachedViewById(I)Landroid/view/View;

    move-result-object v2

    check-cast v2, Landroidx/recyclerview/widget/RecyclerView;

    const-string v3, "recyclerview"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v4, Landroidx/recyclerview/widget/GridLayoutManager;

    invoke-virtual {p0}, Lcom/insecureshop/ProductListActivity;->getApplicationContext()Landroid/content/Context;

    move-result-object v5

    const/4 v6, 0x2

    invoke-direct {v4, v5, v6}, Landroidx/recyclerview/widget/GridLayoutManager;-><init>(Landroid/content/Context;I)V

    check-cast v4, Landroidx/recyclerview/widget/RecyclerView$LayoutManager;

    invoke-virtual {v2, v4}, Landroidx/recyclerview/widget/RecyclerView;->setLayoutManager(Landroidx/recyclerview/widget/RecyclerView$LayoutManager;)V

    .line 34
    sget v2, Lcom/insecureshop/R$id;->recyclerview:I

    invoke-virtual {p0, v2}, Lcom/insecureshop/ProductListActivity;->_$_findCachedViewById(I)Landroid/view/View;

    move-result-object v2

    check-cast v2, Landroidx/recyclerview/widget/RecyclerView;

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v3, v1

    check-cast v3, Landroidx/recyclerview/widget/RecyclerView$Adapter;

    invoke-virtual {v2, v3}, Landroidx/recyclerview/widget/RecyclerView;->setAdapter(Landroidx/recyclerview/widget/RecyclerView$Adapter;)V

    .line 35
    sget-object v2, Lcom/insecureshop/util/Util;->INSTANCE:Lcom/insecureshop/util/Util;

    move-object v3, p0

    check-cast v3, Landroid/content/Context;

    invoke-virtual {v2, v3}, Lcom/insecureshop/util/Util;->getProductsPrefs(Landroid/content/Context;)Ljava/util/List;

    move-result-object v2

    invoke-virtual {v1, v2}, Lcom/insecureshop/ProductAdapter;->setProductList(Ljava/util/List;)V

    .line 36
    invoke-virtual {v1}, Lcom/insecureshop/ProductAdapter;->notifyDataSetChanged()V

    .line 37
    return-void
.end method

.method public onCreateOptionsMenu(Landroid/view/Menu;)Z
    .locals 2
    .param p1, "menu"    # Landroid/view/Menu;

    .line 40
    invoke-virtual {p0}, Lcom/insecureshop/ProductListActivity;->getMenuInflater()Landroid/view/MenuInflater;

    move-result-object v0

    const/high16 v1, 0x7f0d0000

    invoke-virtual {v0, v1, p1}, Landroid/view/MenuInflater;->inflate(ILandroid/view/Menu;)V

    .line 41
    const/4 v0, 0x1

    return v0
.end method

.method public onOptionsItemSelected(Landroid/view/MenuItem;)Z
    .locals 3
    .param p1, "item"    # Landroid/view/MenuItem;

    const-string v0, "item"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onOptionsItemSelected(Landroid/view/MenuItem;)Z

    .line 46
    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v0

    const v1, 0x7f0900a6

    if-ne v0, v1, :cond_0

    .line 47
    sget-object v0, Lcom/insecureshop/util/Prefs;->INSTANCE:Lcom/insecureshop/util/Prefs;

    invoke-virtual {p0}, Lcom/insecureshop/ProductListActivity;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    const-string v2, "applicationContext"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Lcom/insecureshop/util/Prefs;->getInstance(Landroid/content/Context;)Lcom/insecureshop/util/Prefs;

    move-result-object v0

    invoke-virtual {v0}, Lcom/insecureshop/util/Prefs;->clearAll()V

    .line 48
    new-instance v0, Landroid/content/Intent;

    move-object v1, p0

    check-cast v1, Landroid/content/Context;

    const-class v2, Lcom/insecureshop/LoginActivity;

    invoke-direct {v0, v1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 49
    .local v0, "intent":Landroid/content/Intent;
    invoke-virtual {p0, v0}, Lcom/insecureshop/ProductListActivity;->startActivity(Landroid/content/Intent;)V

    .line 50
    invoke-virtual {p0}, Lcom/insecureshop/ProductListActivity;->finish()V

    .line 52
    .end local v0    # "intent":Landroid/content/Intent;
    :cond_0
    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v0

    const v1, 0x7f090051

    if-ne v0, v1, :cond_1

    .line 53
    new-instance v0, Landroid/content/Intent;

    move-object v1, p0

    check-cast v1, Landroid/content/Context;

    const-class v2, Lcom/insecureshop/CartListActivity;

    invoke-direct {v0, v1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 54
    .restart local v0    # "intent":Landroid/content/Intent;
    invoke-virtual {p0, v0}, Lcom/insecureshop/ProductListActivity;->startActivity(Landroid/content/Intent;)V

    .line 56
    .end local v0    # "intent":Landroid/content/Intent;
    :cond_1
    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v0

    const v1, 0x7f09000a

    if-ne v0, v1, :cond_2

    .line 57
    new-instance v0, Landroid/content/Intent;

    move-object v1, p0

    check-cast v1, Landroid/content/Context;

    const-class v2, Lcom/insecureshop/AboutUsActivity;

    invoke-direct {v0, v1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 58
    .restart local v0    # "intent":Landroid/content/Intent;
    invoke-virtual {p0, v0}, Lcom/insecureshop/ProductListActivity;->startActivity(Landroid/content/Intent;)V

    .line 60
    .end local v0    # "intent":Landroid/content/Intent;
    :cond_2
    const/4 v0, 0x1

    return v0
.end method
