.class public abstract Lcom/insecureshop/databinding/UploadSuccessDialogBinding;
.super Landroidx/databinding/ViewDataBinding;
.source "UploadSuccessDialogBinding.java"


# instance fields
.field public final btnOk:Landroidx/appcompat/widget/AppCompatButton;

.field public final tvMessage:Landroidx/appcompat/widget/AppCompatTextView;

.field public final tvSuccess:Landroidx/appcompat/widget/AppCompatTextView;


# direct methods
.method protected constructor <init>(Ljava/lang/Object;Landroid/view/View;ILandroidx/appcompat/widget/AppCompatButton;Landroidx/appcompat/widget/AppCompatTextView;Landroidx/appcompat/widget/AppCompatTextView;)V
    .locals 0
    .param p1, "_bindingComponent"    # Ljava/lang/Object;
    .param p2, "_root"    # Landroid/view/View;
    .param p3, "_localFieldCount"    # I
    .param p4, "btnOk"    # Landroidx/appcompat/widget/AppCompatButton;
    .param p5, "tvMessage"    # Landroidx/appcompat/widget/AppCompatTextView;
    .param p6, "tvSuccess"    # Landroidx/appcompat/widget/AppCompatTextView;

    .line 29
    invoke-direct {p0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;-><init>(Ljava/lang/Object;Landroid/view/View;I)V

    .line 30
    iput-object p4, p0, Lcom/insecureshop/databinding/UploadSuccessDialogBinding;->btnOk:Landroidx/appcompat/widget/AppCompatButton;

    .line 31
    iput-object p5, p0, Lcom/insecureshop/databinding/UploadSuccessDialogBinding;->tvMessage:Landroidx/appcompat/widget/AppCompatTextView;

    .line 32
    iput-object p6, p0, Lcom/insecureshop/databinding/UploadSuccessDialogBinding;->tvSuccess:Landroidx/appcompat/widget/AppCompatTextView;

    .line 33
    return-void
.end method

.method public static bind(Landroid/view/View;)Lcom/insecureshop/databinding/UploadSuccessDialogBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;

    .line 75
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/UploadSuccessDialogBinding;->bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/UploadSuccessDialogBinding;

    move-result-object v0

    return-object v0
.end method

.method public static bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/UploadSuccessDialogBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 87
    const v0, 0x7f0c0076

    invoke-static {p1, p0, v0}, Lcom/insecureshop/databinding/UploadSuccessDialogBinding;->bind(Ljava/lang/Object;Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/UploadSuccessDialogBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;)Lcom/insecureshop/databinding/UploadSuccessDialogBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;

    .line 57
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/UploadSuccessDialogBinding;->inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/UploadSuccessDialogBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Z)Lcom/insecureshop/databinding/UploadSuccessDialogBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z

    .line 38
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, p1, p2, v0}, Lcom/insecureshop/databinding/UploadSuccessDialogBinding;->inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/UploadSuccessDialogBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/UploadSuccessDialogBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z
    .param p3, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 52
    const v0, 0x7f0c0076

    invoke-static {p0, v0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/UploadSuccessDialogBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/UploadSuccessDialogBinding;
    .locals 3
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 71
    const v0, 0x7f0c0076

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-static {p0, v0, v1, v2, p1}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/UploadSuccessDialogBinding;

    return-object v0
.end method
