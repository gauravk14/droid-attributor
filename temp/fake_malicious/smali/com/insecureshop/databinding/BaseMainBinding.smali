.class public abstract Lcom/insecureshop/databinding/BaseMainBinding;
.super Landroidx/databinding/ViewDataBinding;
.source "BaseMainBinding.java"


# instance fields
.field public final container:Landroid/widget/FrameLayout;

.field public final linToolbar:Landroid/widget/LinearLayout;

.field public final toolbar:Lcom/insecureshop/databinding/ToolbarBinding;


# direct methods
.method protected constructor <init>(Ljava/lang/Object;Landroid/view/View;ILandroid/widget/FrameLayout;Landroid/widget/LinearLayout;Lcom/insecureshop/databinding/ToolbarBinding;)V
    .locals 0
    .param p1, "_bindingComponent"    # Ljava/lang/Object;
    .param p2, "_root"    # Landroid/view/View;
    .param p3, "_localFieldCount"    # I
    .param p4, "container"    # Landroid/widget/FrameLayout;
    .param p5, "linToolbar"    # Landroid/widget/LinearLayout;
    .param p6, "toolbar"    # Lcom/insecureshop/databinding/ToolbarBinding;

    .line 29
    invoke-direct {p0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;-><init>(Ljava/lang/Object;Landroid/view/View;I)V

    .line 30
    iput-object p4, p0, Lcom/insecureshop/databinding/BaseMainBinding;->container:Landroid/widget/FrameLayout;

    .line 31
    iput-object p5, p0, Lcom/insecureshop/databinding/BaseMainBinding;->linToolbar:Landroid/widget/LinearLayout;

    .line 32
    iput-object p6, p0, Lcom/insecureshop/databinding/BaseMainBinding;->toolbar:Lcom/insecureshop/databinding/ToolbarBinding;

    .line 33
    invoke-virtual {p0, p6}, Lcom/insecureshop/databinding/BaseMainBinding;->setContainedBinding(Landroidx/databinding/ViewDataBinding;)V

    .line 34
    return-void
.end method

.method public static bind(Landroid/view/View;)Lcom/insecureshop/databinding/BaseMainBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;

    .line 76
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/BaseMainBinding;->bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/BaseMainBinding;

    move-result-object v0

    return-object v0
.end method

.method public static bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/BaseMainBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 88
    const v0, 0x7f0c0026

    invoke-static {p1, p0, v0}, Lcom/insecureshop/databinding/BaseMainBinding;->bind(Ljava/lang/Object;Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/BaseMainBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;)Lcom/insecureshop/databinding/BaseMainBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;

    .line 58
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/BaseMainBinding;->inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/BaseMainBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Z)Lcom/insecureshop/databinding/BaseMainBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z

    .line 39
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, p1, p2, v0}, Lcom/insecureshop/databinding/BaseMainBinding;->inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/BaseMainBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/BaseMainBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z
    .param p3, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 53
    const v0, 0x7f0c0026

    invoke-static {p0, v0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/BaseMainBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/BaseMainBinding;
    .locals 3
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 72
    const v0, 0x7f0c0026

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-static {p0, v0, v1, v2, p1}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/BaseMainBinding;

    return-object v0
.end method
