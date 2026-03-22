.class public final Lcom/insecureshop/WebView2Activity;
.super Landroidx/appcompat/app/AppCompatActivity;
.source "WebView2Activity.kt"


# annotations
.annotation system Ldalvik/annotation/SourceDebugExtension;
    value = "SMAP\nWebView2Activity.kt\nKotlin\n*S Kotlin\n*F\n+ 1 WebView2Activity.kt\ncom/insecureshop/WebView2Activity\n*L\n1#1,44:1\n*E\n"
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
        "Lcom/insecureshop/WebView2Activity;",
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

    .line 10
    invoke-direct {p0}, Landroidx/appcompat/app/AppCompatActivity;-><init>()V

    .line 13
    const-string v0, "Mozilla/5.0 (Linux; Android 4.1.1; Galaxy Nexus Build/JRO03C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.65 Mobile Safari/537.36"

    iput-object v0, p0, Lcom/insecureshop/WebView2Activity;->USER_AGENT:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public _$_clearFindViewByIdCache()V
    .locals 1

    iget-object v0, p0, Lcom/insecureshop/WebView2Activity;->_$_findViewCache:Ljava/util/HashMap;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    :cond_0
    return-void
.end method

.method public _$_findCachedViewById(I)Landroid/view/View;
    .locals 2

    iget-object v0, p0, Lcom/insecureshop/WebView2Activity;->_$_findViewCache:Ljava/util/HashMap;

    if-nez v0, :cond_0

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lcom/insecureshop/WebView2Activity;->_$_findViewCache:Ljava/util/HashMap;

    :cond_0
    iget-object v0, p0, Lcom/insecureshop/WebView2Activity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    if-nez v0, :cond_1

    invoke-virtual {p0, p1}, Landroidx/fragment/app/FragmentActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    iget-object v1, p0, Lcom/insecureshop/WebView2Activity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {v1, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    return-object v0
.end method

.method public final getUSER_AGENT()Ljava/lang/String;
    .locals 1

    .line 12
    iget-object v0, p0, Lcom/insecureshop/WebView2Activity;->USER_AGENT:Ljava/lang/String;

    return-object v0
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 8
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .line 16
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V

    .line 17
    const v0, 0x7f0c0024

    invoke-virtual {p0, v0}, Lcom/insecureshop/WebView2Activity;->setContentView(I)V

    .line 18
    sget v0, Lcom/insecureshop/R$id;->toolbar:I

    invoke-virtual {p0, v0}, Lcom/insecureshop/WebView2Activity;->_$_findCachedViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p0, v0}, Lcom/insecureshop/WebView2Activity;->setSupportActionBar(Landroidx/appcompat/widget/Toolbar;)V

    .line 19
    const v0, 0x7f100067

    invoke-virtual {p0, v0}, Lcom/insecureshop/WebView2Activity;->getString(I)Ljava/lang/String;

    move-result-object v0

    check-cast v0, Ljava/lang/CharSequence;

    invoke-virtual {p0, v0}, Lcom/insecureshop/WebView2Activity;->setTitle(Ljava/lang/CharSequence;)V

    .line 21
    invoke-virtual {p0}, Lcom/insecureshop/WebView2Activity;->getIntent()Landroid/content/Intent;

    move-result-object v0

    const-string v1, "extra_intent"

    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    move-result-object v0

    check-cast v0, Landroid/content/Intent;

    .line 22
    .local v0, "extraIntent":Landroid/content/Intent;
    if-eqz v0, :cond_0

    .line 23
    invoke-virtual {p0, v0}, Lcom/insecureshop/WebView2Activity;->startActivity(Landroid/content/Intent;)V

    .line 24
    invoke-virtual {p0}, Lcom/insecureshop/WebView2Activity;->finish()V

    .line 25
    return-void

    .line 28
    :cond_0
    const v1, 0x7f09014a

    invoke-virtual {p0, v1}, Lcom/insecureshop/WebView2Activity;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/webkit/WebView;

    .line 30
    .local v1, "webview":Landroid/webkit/WebView;
    const-string v2, "webview"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v2

    const-string v3, "webview.settings"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v4, 0x1

    invoke-virtual {v2, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    .line 31
    invoke-virtual {v1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v2

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2, v4}, Landroid/webkit/WebSettings;->setLoadWithOverviewMode(Z)V

    .line 32
    invoke-virtual {v1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v2

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2, v4}, Landroid/webkit/WebSettings;->setUseWideViewPort(Z)V

    .line 33
    invoke-virtual {v1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v2

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2, v4}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V

    .line 34
    invoke-virtual {v1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;

    move-result-object v2

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v3, p0, Lcom/insecureshop/WebView2Activity;->USER_AGENT:Ljava/lang/String;

    invoke-virtual {v2, v3}, Landroid/webkit/WebSettings;->setUserAgentString(Ljava/lang/String;)V

    .line 35
    invoke-virtual {p0}, Lcom/insecureshop/WebView2Activity;->getIntent()Landroid/content/Intent;

    move-result-object v2

    const-string v3, "intent"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Landroid/content/Intent;->getDataString()Ljava/lang/String;

    move-result-object v2

    check-cast v2, Ljava/lang/CharSequence;

    const/4 v5, 0x0

    if-eqz v2, :cond_2

    invoke-static {v2}, Lkotlin/text/StringsKt;->isBlank(Ljava/lang/CharSequence;)Z

    move-result v2

    if-eqz v2, :cond_1

    goto :goto_0

    :cond_1
    const/4 v2, 0x0

    goto :goto_1

    :cond_2
    :goto_0
    const/4 v2, 0x1

    :goto_1
    if-nez v2, :cond_3

    .line 36
    invoke-virtual {p0}, Lcom/insecureshop/WebView2Activity;->getIntent()Landroid/content/Intent;

    move-result-object v2

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Landroid/content/Intent;->getDataString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    goto/16 :goto_7

    .line 37
    :cond_3
    invoke-virtual {p0}, Lcom/insecureshop/WebView2Activity;->getIntent()Landroid/content/Intent;

    move-result-object v2

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    move-result-object v2

    const-string v6, "url"

    const/4 v7, 0x0

    if-eqz v2, :cond_4

    invoke-virtual {v2, v6}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    goto :goto_2

    :cond_4
    move-object v2, v7

    :goto_2
    check-cast v2, Ljava/lang/CharSequence;

    if-eqz v2, :cond_6

    invoke-static {v2}, Lkotlin/text/StringsKt;->isBlank(Ljava/lang/CharSequence;)Z

    move-result v2

    if-eqz v2, :cond_5

    goto :goto_3

    :cond_5
    const/4 v2, 0x0

    goto :goto_4

    :cond_6
    :goto_3
    const/4 v2, 0x1

    :goto_4
    if-nez v2, :cond_8

    .line 38
    invoke-virtual {p0}, Lcom/insecureshop/WebView2Activity;->getIntent()Landroid/content/Intent;

    move-result-object v2

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    move-result-object v2

    if-eqz v2, :cond_7

    invoke-virtual {v2, v6}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    :cond_7
    invoke-virtual {v1, v7}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    goto :goto_7

    .line 39
    :cond_8
    invoke-virtual {p0}, Lcom/insecureshop/WebView2Activity;->getIntent()Landroid/content/Intent;

    move-result-object v2

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    move-result-object v2

    if-eqz v2, :cond_9

    invoke-virtual {v2, v6}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    goto :goto_5

    :cond_9
    move-object v2, v7

    :goto_5
    check-cast v2, Ljava/lang/CharSequence;

    if-eqz v2, :cond_b

    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    move-result v2

    if-nez v2, :cond_a

    goto :goto_6

    :cond_a
    const/4 v4, 0x0

    :cond_b
    :goto_6
    if-nez v4, :cond_d

    .line 40
    invoke-virtual {p0}, Lcom/insecureshop/WebView2Activity;->getIntent()Landroid/content/Intent;

    move-result-object v2

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    move-result-object v2

    if-eqz v2, :cond_c

    invoke-virtual {v2, v6}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    :cond_c
    invoke-virtual {v1, v7}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    .line 41
    :cond_d
    :goto_7
    nop

    .line 42
    return-void
.end method
