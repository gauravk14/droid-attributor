.class public final Lcom/insecureshop/LoginActivity;
.super Landroidx/appcompat/app/AppCompatActivity;
.source "LoginActivity.kt"


# annotations
.annotation runtime Lkotlin/Metadata;
    bv = {
        0x1,
        0x0,
        0x3
    }
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0005\u00a2\u0006\u0002\u0010\u0002J\u0012\u0010\t\u001a\u00020\n2\u0008\u0010\u000b\u001a\u0004\u0018\u00010\u000cH\u0015J\u000e\u0010\r\u001a\u00020\n2\u0006\u0010\u000e\u001a\u00020\u000fR\u001a\u0010\u0003\u001a\u00020\u0004X\u0086.\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0005\u0010\u0006\"\u0004\u0008\u0007\u0010\u0008\u00a8\u0006\u0010"
    }
    d2 = {
        "Lcom/insecureshop/LoginActivity;",
        "Landroidx/appcompat/app/AppCompatActivity;",
        "()V",
        "mBinding",
        "Lcom/insecureshop/databinding/ActivityLoginBinding;",
        "getMBinding",
        "()Lcom/insecureshop/databinding/ActivityLoginBinding;",
        "setMBinding",
        "(Lcom/insecureshop/databinding/ActivityLoginBinding;)V",
        "onCreate",
        "",
        "savedInstanceState",
        "Landroid/os/Bundle;",
        "onLogin",
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

.field public mBinding:Lcom/insecureshop/databinding/ActivityLoginBinding;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 18
    invoke-direct {p0}, Landroidx/appcompat/app/AppCompatActivity;-><init>()V

    return-void
.end method


# virtual methods
.method public _$_clearFindViewByIdCache()V
    .locals 1

    iget-object v0, p0, Lcom/insecureshop/LoginActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    :cond_0
    return-void
.end method

.method public _$_findCachedViewById(I)Landroid/view/View;
    .locals 2

    iget-object v0, p0, Lcom/insecureshop/LoginActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-nez v0, :cond_0

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lcom/insecureshop/LoginActivity;->_$_findViewCache:Ljava/util/HashMap;

    :cond_0
    iget-object v0, p0, Lcom/insecureshop/LoginActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    if-nez v0, :cond_1

    invoke-virtual {p0, p1}, Landroidx/fragment/app/FragmentActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    iget-object v1, p0, Lcom/insecureshop/LoginActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {v1, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    return-object v0
.end method

.method public final getMBinding()Lcom/insecureshop/databinding/ActivityLoginBinding;
    .locals 2

    .line 19
    iget-object v0, p0, Lcom/insecureshop/LoginActivity;->mBinding:Lcom/insecureshop/databinding/ActivityLoginBinding;

    if-nez v0, :cond_0

    const-string v1, "mBinding"

    invoke-static {v1}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    return-object v0
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .line 23
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V

    .line 24
    nop

    .line 25
    move-object v0, p0

    check-cast v0, Landroid/app/Activity;

    const v1, 0x7f0c0020

    invoke-static {v0, v1}, Landroidx/databinding/DataBindingUtil;->setContentView(Landroid/app/Activity;I)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    const-string v1, "DataBindingUtil.setConte\u2026 R.layout.activity_login)"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Lcom/insecureshop/databinding/ActivityLoginBinding;

    iput-object v0, p0, Lcom/insecureshop/LoginActivity;->mBinding:Lcom/insecureshop/databinding/ActivityLoginBinding;

    .line 26
    nop

    .line 28
    const/4 v0, 0x2

    new-array v0, v0, [Ljava/lang/String;

    const/4 v1, 0x0

    const-string v2, "android.permission.WRITE_EXTERNAL_STORAGE"

    aput-object v2, v0, v1

    const/4 v1, 0x1

    const-string v2, "android.permission.READ_EXTERNAL_STORAGE"

    aput-object v2, v0, v1

    const/16 v1, 0x64

    invoke-virtual {p0, v0, v1}, Lcom/insecureshop/LoginActivity;->requestPermissions([Ljava/lang/String;I)V

    .line 30
    nop

    .line 32
    return-void
.end method

.method public final onLogin(Landroid/view/View;)V
    .locals 17
    .param p1, "view"    # Landroid/view/View;

    move-object/from16 v1, p0

    const-string v0, "view"

    move-object/from16 v2, p1

    invoke-static {v2, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    iget-object v0, v1, Lcom/insecureshop/LoginActivity;->mBinding:Lcom/insecureshop/databinding/ActivityLoginBinding;

    const-string v3, "mBinding"

    if-nez v0, :cond_0

    invoke-static {v3}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_0
    iget-object v0, v0, Lcom/insecureshop/databinding/ActivityLoginBinding;->edtUserName:Lcom/google/android/material/textfield/TextInputEditText;

    const-string v4, "mBinding.edtUserName"

    invoke-static {v0, v4}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Lcom/google/android/material/textfield/TextInputEditText;->getText()Landroid/text/Editable;

    move-result-object v0

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v4

    .line 37
    .local v4, "username":Ljava/lang/String;
    iget-object v0, v1, Lcom/insecureshop/LoginActivity;->mBinding:Lcom/insecureshop/databinding/ActivityLoginBinding;

    if-nez v0, :cond_1

    invoke-static {v3}, Lkotlin/jvm/internal/Intrinsics;->throwUninitializedPropertyAccessException(Ljava/lang/String;)V

    :cond_1
    iget-object v0, v0, Lcom/insecureshop/databinding/ActivityLoginBinding;->edtPassword:Lcom/google/android/material/textfield/TextInputEditText;

    const-string v3, "mBinding.edtPassword"

    invoke-static {v0, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Lcom/google/android/material/textfield/TextInputEditText;->getText()Landroid/text/Editable;

    move-result-object v0

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v3

    .line 39
    .local v3, "password":Ljava/lang/String;
    const-string v0, "userName"

    invoke-static {v0, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 40
    const-string v0, "password"

    invoke-static {v0, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 43
    sget-object v0, Lcom/insecureshop/util/Util;->INSTANCE:Lcom/insecureshop/util/Util;

    invoke-virtual {v0, v4, v3}, Lcom/insecureshop/util/Util;->verifyUserNamePassword(Ljava/lang/String;Ljava/lang/String;)Z

    move-result v5

    .line 44
    .local v5, "auth":Z
    const/4 v0, 0x2

    const/4 v6, 0x0

    if-eqz v5, :cond_2

    .line 45
    sget-object v7, Lcom/insecureshop/util/Prefs;->INSTANCE:Lcom/insecureshop/util/Prefs;

    invoke-virtual/range {p0 .. p0}, Lcom/insecureshop/LoginActivity;->getApplicationContext()Landroid/content/Context;

    move-result-object v8

    const-string v9, "applicationContext"

    invoke-static {v8, v9}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v7, v8}, Lcom/insecureshop/util/Prefs;->getInstance(Landroid/content/Context;)Lcom/insecureshop/util/Prefs;

    move-result-object v7

    invoke-virtual {v7, v4}, Lcom/insecureshop/util/Prefs;->setUsername(Ljava/lang/String;)V

    .line 46
    sget-object v7, Lcom/insecureshop/util/Prefs;->INSTANCE:Lcom/insecureshop/util/Prefs;

    invoke-virtual/range {p0 .. p0}, Lcom/insecureshop/LoginActivity;->getApplicationContext()Landroid/content/Context;

    move-result-object v8

    invoke-static {v8, v9}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v7, v8}, Lcom/insecureshop/util/Prefs;->getInstance(Landroid/content/Context;)Lcom/insecureshop/util/Prefs;

    move-result-object v7

    invoke-virtual {v7, v3}, Lcom/insecureshop/util/Prefs;->setPassword(Ljava/lang/String;)V

    .line 47
    sget-object v7, Lcom/insecureshop/util/Util;->INSTANCE:Lcom/insecureshop/util/Util;

    move-object v8, v1

    check-cast v8, Landroid/content/Context;

    invoke-static {v7, v8, v6, v0, v6}, Lcom/insecureshop/util/Util;->saveProductList$default(Lcom/insecureshop/util/Util;Landroid/content/Context;Ljava/util/List;ILjava/lang/Object;)V

    .line 48
    new-instance v0, Landroid/content/Intent;

    move-object v6, v1

    check-cast v6, Landroid/content/Context;

    const-class v7, Lcom/insecureshop/ProductListActivity;

    invoke-direct {v0, v6, v7}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 49
    .local v0, "intent":Landroid/content/Intent;
    invoke-virtual {v1, v0}, Lcom/insecureshop/LoginActivity;->startActivity(Landroid/content/Intent;)V

    .end local v0    # "intent":Landroid/content/Intent;
    goto/16 :goto_2

    .line 51
    :cond_2
    invoke-virtual/range {p0 .. p0}, Lcom/insecureshop/LoginActivity;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v7

    const/4 v8, 0x0

    invoke-virtual {v7, v8}, Landroid/content/pm/PackageManager;->getInstalledPackages(I)Ljava/util/List;

    move-result-object v7

    invoke-interface {v7}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :goto_0
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    const/4 v10, 0x1

    if-eqz v9, :cond_4

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Landroid/content/pm/PackageInfo;

    .line 52
    .local v9, "info":Landroid/content/pm/PackageInfo;
    iget-object v11, v9, Landroid/content/pm/PackageInfo;->packageName:Ljava/lang/String;

    .line 53
    .local v11, "packageName":Ljava/lang/String;
    const-string v12, "packageName"

    invoke-static {v11, v12}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v12, "com.insecureshopapp"

    invoke-static {v11, v12, v8, v0, v6}, Lkotlin/text/StringsKt;->startsWith$default(Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_3

    .line 54
    nop

    .line 55
    const/4 v12, 0x3

    :try_start_0
    invoke-virtual {v1, v11, v12}, Lcom/insecureshop/LoginActivity;->createPackageContext(Ljava/lang/String;I)Landroid/content/Context;

    move-result-object v12

    .line 56
    .local v12, "packageContext":Landroid/content/Context;
    nop

    .line 59
    nop

    .line 56
    nop

    .line 58
    nop

    .line 56
    nop

    .line 57
    nop

    .line 56
    const-string v13, "packageContext"

    invoke-static {v12, v13}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v12}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v13

    .line 57
    const-string v14, "com.insecureshopapp.MainInterface"

    invoke-virtual {v13, v14}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v13

    .line 58
    const-string v14, "getInstance"

    new-array v15, v10, [Ljava/lang/Class;

    const-class v16, Landroid/content/Context;

    aput-object v16, v15, v8

    invoke-virtual {v13, v14, v15}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v13

    .line 59
    new-array v10, v10, [Ljava/lang/Object;

    aput-object v1, v10, v8

    invoke-virtual {v13, v6, v10}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    const-string v13, "packageContext.classLoad\u2026      .invoke(null, this)"

    invoke-static {v10, v13}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    nop

    .line 60
    .local v10, "value":Ljava/lang/Object;
    const-string v13, "object_value"

    invoke-virtual {v10}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v14

    invoke-static {v13, v14}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    .line 61
    .end local v10    # "value":Ljava/lang/Object;
    .end local v12    # "packageContext":Landroid/content/Context;
    :catch_0
    move-exception v0

    .line 62
    .local v0, "e":Ljava/lang/Exception;
    new-instance v6, Ljava/lang/RuntimeException;

    move-object v7, v0

    check-cast v7, Ljava/lang/Throwable;

    invoke-direct {v6, v7}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    check-cast v6, Ljava/lang/Throwable;

    throw v6

    .line 63
    .end local v0    # "e":Ljava/lang/Exception;
    .end local v9    # "info":Landroid/content/pm/PackageInfo;
    .end local v11    # "packageName":Ljava/lang/String;
    :cond_3
    :goto_1
    nop

    .line 51
    goto :goto_0

    .line 67
    :cond_4
    nop

    .line 68
    nop

    .line 67
    invoke-virtual/range {p0 .. p0}, Lcom/insecureshop/LoginActivity;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    const-string v6, "Invalid username and password"

    check-cast v6, Ljava/lang/CharSequence;

    invoke-static {v0, v6, v10}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v0

    .line 68
    invoke-virtual {v0}, Landroid/widget/Toast;->show()V

    .line 69
    :goto_2
    nop

    .line 70
    return-void
.end method

.method public final setMBinding(Lcom/insecureshop/databinding/ActivityLoginBinding;)V
    .locals 1
    .param p1, "<set-?>"    # Lcom/insecureshop/databinding/ActivityLoginBinding;

    const-string v0, "<set-?>"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    iput-object p1, p0, Lcom/insecureshop/LoginActivity;->mBinding:Lcom/insecureshop/databinding/ActivityLoginBinding;

    return-void
.end method
