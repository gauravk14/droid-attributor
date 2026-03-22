.class public final Lcom/insecureshop/WebViewActivity;
.super Landroidx/appcompat/app/AppCompatActivity;
.source "WebViewActivity.kt"


# annotations
.annotation system Ldalvik/annotation/SourceDebugExtension;
    value = "SMAP\nWebViewActivity.kt\nKotlin\n*S Kotlin\n*F\n+ 1 WebViewActivity.kt\ncom/insecureshop/WebViewActivity\n*L\n1#1,53:1\n*E\n"
.end annotation

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
        "Lcom/insecureshop/WebViewActivity;",
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

    .line 12
    invoke-direct {p0}, Landroidx/appcompat/app/AppCompatActivity;-><init>()V

    .line 15
    const-string v0, "Mozilla/5.0 (Linux; Android 4.1.1; Galaxy Nexus Build/JRO03C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.65 Mobile Safari/537.36"

    iput-object v0, p0, Lcom/insecureshop/WebViewActivity;->USER_AGENT:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public _$_clearFindViewByIdCache()V
    .locals 1

    iget-object v0, p0, Lcom/insecureshop/WebViewActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    :cond_0
    return-void
.end method

.method public _$_findCachedViewById(I)Landroid/view/View;
    .locals 2

    iget-object v0, p0, Lcom/insecureshop/WebViewActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-nez v0, :cond_0

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lcom/insecureshop/WebViewActivity;->_$_findViewCache:Ljava/util/HashMap;

    :cond_0
    iget-object v0, p0, Lcom/insecureshop/WebViewActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    if-nez v0, :cond_1

    invoke-virtual {p0, p1}, Landroidx/fragment/app/FragmentActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    iget-object v1, p0, Lcom/insecureshop/WebViewActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {v1, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    return-object v0
.end method

.method public final getUSER_AGENT()Ljava/lang/String;
    .locals 1

    .line 14
    iget-object v0, p0, Lcom/insecureshop/WebViewActivity;->USER_AGENT:Ljava/lang/String;

    return-object v0
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 12
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .line 18
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V

    .line 19
    const v0, 0x7f0c0024

    invoke-virtual {p0, v0}, Lcom/insecureshop/WebViewActivity;->setContentView(I)V

    .line 20
    sget v0, Lcom/insecureshop/R$id;->toolbar:I

    invoke-virtual {p0, v0}, Lcom/insecureshop/WebViewActivity;->_$_findCachedViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p0, v0}, Lcom/insecureshop/WebViewActivity;->setSupportActionBar(Landroidx/appcompat/widget/Toolbar;)V

    .line 21
    const v0, 0x7f100067

    invoke-virtual {p0, v0}, Lcom/insecureshop/WebViewActivity;->getString(I)Ljava/lang/String;

    move-result-object v0

    check-cast v0, Ljava/lang/CharSequence;

    invoke-virtual {p0, v0}, Lcom/insecureshop/WebViewActivity;->setTitle(Ljava/lang/CharSequence;)V

    .line 23
    const v0, 0x7f09014a

    invoke-virtual {p0, v0}, Lcom/insecureshop/WebViewActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/webkit/WebView;

    .line 25
    .local v0, "webview":Landroid/webkit/WebView;
    const-string v1, "webview"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v1

    const-string v2, "webview.settings"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v3, 0x1

    invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    .line 26
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setLoadWithOverviewMode(Z)V

    .line 27
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setUseWideViewPort(Z)V

    .line 28
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V

    .line 29
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v1

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, p0, Lcom/insecureshop/WebViewActivity;->USER_AGENT:Ljava/lang/String;

    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setUserAgentString(Ljava/lang/String;)V

    .line 30
    new-instance v1, Lcom/insecureshop/util/CustomWebViewClient;

    invoke-direct {v1}, Lcom/insecureshop/util/CustomWebViewClient;-><init>()V

    check-cast v1, Landroid/webkit/WebViewClient;

    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->setWebViewClient(Landroid/webkit/WebViewClient;)V

    .line 31
    invoke-virtual {p0}, Lcom/insecureshop/WebViewActivity;->getIntent()Landroid/content/Intent;

    move-result-object v1

    const-string v2, "intent"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    move-result-object v1

    .line 32
    .local v1, "uri":Landroid/net/Uri;
    if-eqz v1, :cond_7

    move-object v3, v1

    .local v3, "it":Landroid/net/Uri;
    const/4 v4, 0x0

    .line 33
    .local v4, "$i$a$-let-WebViewActivity$onCreate$1":I
    const/4 v5, 0x0

    move-object v6, v5

    check-cast v6, Ljava/lang/String;

    .line 34
    .local v6, "data":Ljava/lang/String;
    invoke-virtual {v1}, Landroid/net/Uri;->getPath()Ljava/lang/String;

    move-result-object v7

    const/4 v8, 0x2

    const/4 v9, 0x0

    const-string v10, "/web"

    invoke-static {v7, v10, v9, v8, v5}, Lkotlin/text/StringsKt;->equals$default(Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Z

    move-result v7

    const-string v10, "url"

    if-eqz v7, :cond_1

    .line 35
    invoke-virtual {p0}, Lcom/insecureshop/WebViewActivity;->getIntent()Landroid/content/Intent;

    move-result-object v7

    invoke-static {v7, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v7}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    move-result-object v2

    if-eqz v2, :cond_0

    invoke-virtual {v2, v10}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    :cond_0
    move-object v6, v5

    goto :goto_0

    .line 36
    :cond_1
    invoke-virtual {v1}, Landroid/net/Uri;->getPath()Ljava/lang/String;

    move-result-object v7

    const-string v11, "/webview"

    invoke-static {v7, v11, v9, v8, v5}, Lkotlin/text/StringsKt;->equals$default(Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_5

    .line 37
    invoke-virtual {p0}, Lcom/insecureshop/WebViewActivity;->getIntent()Landroid/content/Intent;

    move-result-object v7

    invoke-static {v7, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v7}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    move-result-object v7

    if-nez v7, :cond_2

    invoke-static {}, Lkotlin/jvm/internal/Intrinsics;->throwNpe()V

    :cond_2
    invoke-virtual {v7, v10}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    if-nez v7, :cond_3

    invoke-static {}, Lkotlin/jvm/internal/Intrinsics;->throwNpe()V

    :cond_3
    const-string v11, "intent.data!!.getQueryParameter(\"url\")!!"

    invoke-static {v7, v11}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "insecureshopapp.com"

    invoke-static {v7, v11, v9, v8, v5}, Lkotlin/text/StringsKt;->endsWith$default(Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_5

    .line 38
    invoke-virtual {p0}, Lcom/insecureshop/WebViewActivity;->getIntent()Landroid/content/Intent;

    move-result-object v7

    invoke-static {v7, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v7}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    move-result-object v2

    if-eqz v2, :cond_4

    invoke-virtual {v2, v10}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    :cond_4
    move-object v6, v5

    .line 40
    :cond_5
    :goto_0
    nop

    .line 42
    if-nez v6, :cond_6

    .line 43
    invoke-virtual {p0}, Lcom/insecureshop/WebViewActivity;->finish()V

    .line 45
    :cond_6
    invoke-virtual {v0, v6}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    .line 46
    sget-object v2, Lcom/insecureshop/util/Prefs;->INSTANCE:Lcom/insecureshop/util/Prefs;

    move-object v5, p0

    check-cast v5, Landroid/content/Context;

    invoke-virtual {v2, v5}, Lcom/insecureshop/util/Prefs;->getInstance(Landroid/content/Context;)Lcom/insecureshop/util/Prefs;

    move-result-object v2

    invoke-virtual {v2, v6}, Lcom/insecureshop/util/Prefs;->setData(Ljava/lang/String;)V

    .line 47
    .end local v6    # "data":Ljava/lang/String;
    nop

    .line 32
    .end local v3    # "it":Landroid/net/Uri;
    .end local v4    # "$i$a$-let-WebViewActivity$onCreate$1":I
    nop

    .line 49
    :cond_7
    return-void
.end method
