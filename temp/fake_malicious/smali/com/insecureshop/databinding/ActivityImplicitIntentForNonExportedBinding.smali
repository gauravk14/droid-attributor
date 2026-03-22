.class public abstract Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;
.super Landroidx/databinding/ViewDataBinding;
.source "ActivityImplicitIntentForNonExportedBinding.java"


# instance fields
.field public final logout:Landroid/widget/Button;

.field public final toolbar:Landroidx/appcompat/widget/Toolbar;


# direct methods
.method protected constructor <init>(Ljava/lang/Object;Landroid/view/View;ILandroid/widget/Button;Landroidx/appcompat/widget/Toolbar;)V
    .locals 0
    .param p1, "_bindingComponent"    # Ljava/lang/Object;
    .param p2, "_root"    # Landroid/view/View;
    .param p3, "_localFieldCount"    # I
    .param p4, "logout"    # Landroid/widget/Button;
    .param p5, "toolbar"    # Landroidx/appcompat/widget/Toolbar;

    .line 26
    invoke-direct {p0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;-><init>(Ljava/lang/Object;Landroid/view/View;I)V

    .line 27
    iput-object p4, p0, Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;->logout:Landroid/widget/Button;

    .line 28
    iput-object p5, p0, Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;->toolbar:Landroidx/appcompat/widget/Toolbar;

    .line 29
    return-void
.end method

.method public static bind(Landroid/view/View;)Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;

    .line 73
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;->bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;

    move-result-object v0

    return-object v0
.end method

.method public static bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 86
    const v0, 0x7f0c001f

    invoke-static {p1, p0, v0}, Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;->bind(Ljava/lang/Object;Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;)Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;

    .line 55
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;->inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Z)Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z

    .line 34
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, p1, p2, v0}, Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;->inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z
    .param p3, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 49
    const v0, 0x7f0c001f

    invoke-static {p0, v0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;
    .locals 3
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 69
    const v0, 0x7f0c001f

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-static {p0, v0, v1, v2, p1}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBinding;

    return-object v0
.end method
