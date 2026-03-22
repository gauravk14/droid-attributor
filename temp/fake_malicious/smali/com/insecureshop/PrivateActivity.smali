.class public final Lcom/insecureshop/PrivateActivity;
.super Landroidx/appcompat/app/AppCompatActivity;
.source "PrivateActivity.kt"


# annotations
.annotation runtime Lkotlin/Metadata;
    bv = {
        0x1,
        0x0,
        0x3
    }
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0005\u00a2\u0006\u0002\u0010\u0002J\u0012\u0010\u0007\u001a\u00020\u00082\u0008\u0010\t\u001a\u0004\u0018\u00010\nH\u0014R\u0014\u0010\u0003\u001a\u00020\u0004X\u0086D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0005\u0010\u0006\u00a8\u0006\u000b"
    }
    d2 = {
        "Lcom/insecureshop/PrivateActivity;",
        "Landroidx/appcompat/app/AppCompatActivity;",
        "()V",
        "USER_AGENT",
        "",
        "getUSER_AGENT",
        "()Ljava/lang/String;",
        "onCreate",
        "",
        "savedInstanceState",
        "Landroid/os/Bundle;",
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
.field private final USER_AGENT:Ljava/lang/String;

.field private _$_findViewCache:Ljava/util/HashMap;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 11
    invoke-direct {p0}, Landroidx/appcompat/app/AppCompatActivity;-><init>()V

    .line 14
    const-string v0, "Mozilla/5.0 (Linux; Android 4.1.1; Galaxy Nexus Build/JRO03C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.65 Mobile Safari/537.36"

    iput-object v0, p0, Lcom/insecureshop/PrivateActivity;->USER_AGENT:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public _$_clearFindViewByIdCache()V
    .locals 1

    iget-object v0, p0, Lcom/insecureshop/PrivateActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    :cond_0
    return-void
.end method

.method public _$_findCachedViewById(I)Landroid/view/View;
    .locals 2

    iget-object v0, p0, Lcom/insecureshop/PrivateActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-nez v0, :cond_0

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lcom/insecureshop/PrivateActivity;->_$_findViewCache:Ljava/util/HashMap;

    :cond_0
    iget-object v0, p0, Lcom/insecureshop/PrivateActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    if-nez v0, :cond_1

    invoke-virtual {p0, p1}, Landroidx/fragment/app/FragmentActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    iget-object v1, p0, Lcom/insecureshop/PrivateActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {v1, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    return-object v0
.end method

.method public final getUSER_AGENT()Ljava/lang/String;
    .locals 1

    .line 13
    iget-object v0, p0, Lcom/insecureshop/PrivateActivity;->USER_AGENT:Ljava/lang/String;

    return-object v0
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 5
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .line 17
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V

    .line 18
    const v0, 0x7f0c0022

    invoke-virtual {p0, v0}, Lcom/insecureshop/PrivateActivity;->setContentView(I)V

    .line 19
    sget v0, Lcom/insecureshop/R$id;->toolbar:I

    invoke-virtual {p0, v0}, Lcom/insecureshop/PrivateActivity;->_$_findCachedViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p0, v0}, Lcom/insecureshop/PrivateActivity;->setSupportActionBar(Landroidx/appcompat/widget/Toolbar;)V

    .line 20
    const v0, 0x7f100067

    invoke-virtual {p0, v0}, Lcom/insecureshop/PrivateActivity;->getString(I)Ljava/lang/String;

    move-result-object v0

    check-cast v0, Ljava/lang/CharSequence;

    invoke-virtual {p0, v0}, Lcom/insecureshop/PrivateActivity;->setTitle(Ljava/lang/CharSequence;)V

    .line 22
    const v0, 0x7f09014a

    invoke-virtual {p0, v0}, Lcom/insecureshop/PrivateActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/webkit/WebView;

    .line 24
    .local v0, "webview":Landroid/webkit/WebView;
    const-string v1, "webview"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v1

    const-string v2, "webview.settings"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v3, 0x1

    invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    .line 25
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setLoadWithOverviewMode(Z)V

    .line 26
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setUseWideViewPort(Z)V

    .line 27
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v4, p0, Lcom/insecureshop/PrivateActivity;->USER_AGENT:Ljava/lang/String;

    invoke-virtual {v1, v4}, Landroid/webkit/WebSettings;->setUserAgentString(Ljava/lang/String;)V

    .line 28
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V

    .line 29
    invoke-virtual {p0}, Lcom/insecureshop/PrivateActivity;->getIntent()Landroid/content/Intent;

    move-result-object v1

    const-string v2, "url"

    invoke-virtual {v1, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 30
    .local v1, "data":Ljava/lang/String;
    if-nez v1, :cond_0

    .line 31
    const-string v1, "https://www.insecureshopapp.com"

    .line 34
    :cond_0
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    .line 35
    sget-object v2, Lcom/insecureshop/util/Prefs;->INSTANCE:Lcom/insecureshop/util/Prefs;

    move-object v3, p0

    check-cast v3, Landroid/content/Context;

    invoke-virtual {v2, v3}, Lcom/insecureshop/util/Prefs;->getInstance(Landroid/content/Context;)Lcom/insecureshop/util/Prefs;

    move-result-object v2

    invoke-virtual {v2, v1}, Lcom/insecureshop/util/Prefs;->setData(Ljava/lang/String;)V

    .line 36
    return-void
.end method
