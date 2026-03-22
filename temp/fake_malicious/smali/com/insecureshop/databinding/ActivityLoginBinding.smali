.class public abstract Lcom/insecureshop/databinding/ActivityLoginBinding;
.super Landroidx/databinding/ViewDataBinding;
.source "ActivityLoginBinding.java"


# instance fields
.field public final btnLogin:Landroidx/appcompat/widget/AppCompatButton;

.field public final edtPassword:Lcom/google/android/material/textfield/TextInputEditText;

.field public final edtUserName:Lcom/google/android/material/textfield/TextInputEditText;

.field public final ivTop:Landroidx/appcompat/widget/AppCompatImageView;

.field public final lableLogin:Landroidx/appcompat/widget/AppCompatTextView;

.field public final textInputPassword:Lcom/google/android/material/textfield/TextInputLayout;

.field public final textInputUserName:Lcom/google/android/material/textfield/TextInputLayout;


# direct methods
.method protected constructor <init>(Ljava/lang/Object;Landroid/view/View;ILandroidx/appcompat/widget/AppCompatButton;Lcom/google/android/material/textfield/TextInputEditText;Lcom/google/android/material/textfield/TextInputEditText;Landroidx/appcompat/widget/AppCompatImageView;Landroidx/appcompat/widget/AppCompatTextView;Lcom/google/android/material/textfield/TextInputLayout;Lcom/google/android/material/textfield/TextInputLayout;)V
    .locals 0
    .param p1, "_bindingComponent"    # Ljava/lang/Object;
    .param p2, "_root"    # Landroid/view/View;
    .param p3, "_localFieldCount"    # I
    .param p4, "btnLogin"    # Landroidx/appcompat/widget/AppCompatButton;
    .param p5, "edtPassword"    # Lcom/google/android/material/textfield/TextInputEditText;
    .param p6, "edtUserName"    # Lcom/google/android/material/textfield/TextInputEditText;
    .param p7, "ivTop"    # Landroidx/appcompat/widget/AppCompatImageView;
    .param p8, "lableLogin"    # Landroidx/appcompat/widget/AppCompatTextView;
    .param p9, "textInputPassword"    # Lcom/google/android/material/textfield/TextInputLayout;
    .param p10, "textInputUserName"    # Lcom/google/android/material/textfield/TextInputLayout;

    .line 46
    invoke-direct {p0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;-><init>(Ljava/lang/Object;Landroid/view/View;I)V

    .line 47
    iput-object p4, p0, Lcom/insecureshop/databinding/ActivityLoginBinding;->btnLogin:Landroidx/appcompat/widget/AppCompatButton;

    .line 48
    iput-object p5, p0, Lcom/insecureshop/databinding/ActivityLoginBinding;->edtPassword:Lcom/google/android/material/textfield/TextInputEditText;

    .line 49
    iput-object p6, p0, Lcom/insecureshop/databinding/ActivityLoginBinding;->edtUserName:Lcom/google/android/material/textfield/TextInputEditText;

    .line 50
    iput-object p7, p0, Lcom/insecureshop/databinding/ActivityLoginBinding;->ivTop:Landroidx/appcompat/widget/AppCompatImageView;

    .line 51
    iput-object p8, p0, Lcom/insecureshop/databinding/ActivityLoginBinding;->lableLogin:Landroidx/appcompat/widget/AppCompatTextView;

    .line 52
    iput-object p9, p0, Lcom/insecureshop/databinding/ActivityLoginBinding;->textInputPassword:Lcom/google/android/material/textfield/TextInputLayout;

    .line 53
    iput-object p10, p0, Lcom/insecureshop/databinding/ActivityLoginBinding;->textInputUserName:Lcom/google/android/material/textfield/TextInputLayout;

    .line 54
    return-void
.end method

.method public static bind(Landroid/view/View;)Lcom/insecureshop/databinding/ActivityLoginBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;

    .line 96
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/ActivityLoginBinding;->bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/ActivityLoginBinding;

    move-result-object v0

    return-object v0
.end method

.method public static bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/ActivityLoginBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 108
    const v0, 0x7f0c0020

    invoke-static {p1, p0, v0}, Lcom/insecureshop/databinding/ActivityLoginBinding;->bind(Ljava/lang/Object;Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/ActivityLoginBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;)Lcom/insecureshop/databinding/ActivityLoginBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;

    .line 78
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/ActivityLoginBinding;->inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/ActivityLoginBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Z)Lcom/insecureshop/databinding/ActivityLoginBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z

    .line 59
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, p1, p2, v0}, Lcom/insecureshop/databinding/ActivityLoginBinding;->inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/ActivityLoginBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/ActivityLoginBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z
    .param p3, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 73
    const v0, 0x7f0c0020

    invoke-static {p0, v0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/ActivityLoginBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/ActivityLoginBinding;
    .locals 3
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 92
    const v0, 0x7f0c0020

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-static {p0, v0, v1, v2, p1}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/ActivityLoginBinding;

    return-object v0
.end method
