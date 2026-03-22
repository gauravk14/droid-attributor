.class public final Lcom/insecureshop/AboutUsActivity;
.super Landroidx/appcompat/app/AppCompatActivity;
.source "AboutUsActivity.kt"


# annotations
.annotation runtime Lkotlin/Metadata;
    bv = {
        0x1,
        0x0,
        0x3
    }
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0005\u00a2\u0006\u0002\u0010\u0002J\u0012\u0010\t\u001a\u00020\n2\u0008\u0010\u000b\u001a\u0004\u0018\u00010\u000cH\u0014J\u0008\u0010\r\u001a\u00020\nH\u0014J\u000e\u0010\u000e\u001a\u00020\n2\u0006\u0010\u000f\u001a\u00020\u0010R\u001a\u0010\u0003\u001a\u00020\u0004X\u0086.\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0005\u0010\u0006\"\u0004\u0008\u0007\u0010\u0008\u00a8\u0006\u0011"
    }
    d2 = {
        "Lcom/insecureshop/AboutUsActivity;",
        "Landroidx/appcompat/app/AppCompatActivity;",
        "()V",
        "receiver",
        "Lcom/insecureshop/CustomReceiver;",
        "getReceiver",
        "()Lcom/insecureshop/CustomReceiver;",
        "setReceiver",
        "(Lcom/insecureshop/CustomReceiver;)V",
        "onCreate",
        "",
        "savedInstanceState",
        "Landroid/os/Bundle;",
        "onDestroy",
        "onSendData",
        "view",
        "Landroid/view/View;",
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

.field public receiver:Lcom/insecureshop/CustomReceiver;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 12
    invoke-direct {p0}, Landroidx/appcompat/app/AppCompatActivity;-><init>()V

    return-void
.end method


# virtual methods
.method public _$_clearFindViewByIdCache()V
    .locals 1

    iget-object v0, p0, Lcom/insecureshop/AboutUsActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    :cond_0
    return-void
.end method

.method public _$_findCachedViewById(I)Landroid/view/View;
    .locals 2

    iget-object v0, p0, Lcom/insecureshop/AboutUsActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-nez v0, :cond_0

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lcom/insecureshop/AboutUsActivity;->_$_findViewCache:Ljava/util/HashMap;

    :cond_0
    iget-object v0, p0, Lcom/insecureshop/AboutUsActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    if-nez v0, :cond_1

    invoke-virtual {p0, p1}, Landroidx/fragment/app/FragmentActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    iget-object v1, p0, Lcom/insecureshop/AboutUsActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {v1, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    return-object v0
.end method

.method public final getReceiver()Lcom/insecureshop/CustomReceiver;
    .locals 2

    .line 14
    iget-object v0, p0, Lcom/insecureshop/AboutUsActivity;->receiver:Lcom/insecureshop/CustomReceiver;

    if-nez v0, :cond_0

    const-string v1, "receiver"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    return-object v0
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .line 17
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V

    .line 18
    const v0, 0x7f0c001c

    invoke-virtual {p0, v0}, Lcom/insecureshop/AboutUsActivity;->setContentView(I)V

    .line 19
    new-instance v0, Lcom/insecureshop/CustomReceiver;

    invoke-direct {v0}, Lcom/insecureshop/CustomReceiver;-><init>()V

    iput-object v0, p0, Lcom/insecureshop/AboutUsActivity;->receiver:Lcom/insecureshop/CustomReceiver;

    .line 20
    if-nez v0, :cond_0

    const-string v1, "receiver"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    check-cast v0, Landroid/content/BroadcastReceiver;

    new-instance v1, Landroid/content/IntentFilter;

    const-string v2, "com.insecureshop.CUSTOM_INTENT"

    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0, v1}, Lcom/insecureshop/AboutUsActivity;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 21
    return-void
.end method

.method protected onDestroy()V
    .locals 2

    .line 24
    iget-object v0, p0, Lcom/insecureshop/AboutUsActivity;->receiver:Lcom/insecureshop/CustomReceiver;

    if-nez v0, :cond_0

    const-string v1, "receiver"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    check-cast v0, Landroid/content/BroadcastReceiver;

    invoke-virtual {p0, v0}, Lcom/insecureshop/AboutUsActivity;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 25
    invoke-super {p0}, Landroidx/appcompat/app/AppCompatActivity;->onDestroy()V

    .line 26
    return-void
.end method

.method public final onSendData(Landroid/view/View;)V
    .locals 5
    .param p1, "view"    # Landroid/view/View;

    const-string v0, "view"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    sget-object v0, Lcom/insecureshop/util/Prefs;->INSTANCE:Lcom/insecureshop/util/Prefs;

    invoke-virtual {v0}, Lcom/insecureshop/util/Prefs;->getUsername()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-static {}, Lkotlin/jvm/internal/Intrinsics;->throwNpe()V

    .line 30
    .local v0, "userName":Ljava/lang/String;
    :cond_0
    sget-object v1, Lcom/insecureshop/util/Prefs;->INSTANCE:Lcom/insecureshop/util/Prefs;

    invoke-virtual {v1}, Lcom/insecureshop/util/Prefs;->getPassword()Ljava/lang/String;

    move-result-object v1

    if-nez v1, :cond_1

    invoke-static {}, Lkotlin/jvm/internal/Intrinsics;->throwNpe()V

    .line 32
    .local v1, "password":Ljava/lang/String;
    :cond_1
    new-instance v2, Landroid/content/Intent;

    const-string v3, "com.insecureshop.action.BROADCAST"

    invoke-direct {v2, v3}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 33
    .local v2, "intent":Landroid/content/Intent;
    const-string v3, "username"

    invoke-virtual {v2, v3, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 34
    const-string v3, "password"

    invoke-virtual {v2, v3, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 35
    invoke-virtual {p0, v2}, Lcom/insecureshop/AboutUsActivity;->sendBroadcast(Landroid/content/Intent;)V

    .line 37
    sget v3, Lcom/insecureshop/R$id;->textView:I

    invoke-virtual {p0, v3}, Lcom/insecureshop/AboutUsActivity;->_$_findCachedViewById(I)Landroid/view/View;

    move-result-object v3

    check-cast v3, Landroid/widget/TextView;

    const-string v4, "textView"

    invoke-static {v3, v4}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "InsecureShop is an intentionally designed vulnerable android app built in Kotlin."

    check-cast v4, Ljava/lang/CharSequence;

    invoke-virtual {v3, v4}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 39
    return-void
.end method

.method public final setReceiver(Lcom/insecureshop/CustomReceiver;)V
    .locals 1
    .param p1, "<set-?>"    # Lcom/insecureshop/CustomReceiver;

    const-string v0, "<set-?>"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    iput-object p1, p0, Lcom/insecureshop/AboutUsActivity;->receiver:Lcom/insecureshop/CustomReceiver;

    return-void
.end method
