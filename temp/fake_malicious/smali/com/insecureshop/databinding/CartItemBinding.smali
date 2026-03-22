.class public abstract Lcom/insecureshop/databinding/CartItemBinding;
.super Landroidx/databinding/ViewDataBinding;
.source "CartItemBinding.java"


# instance fields
.field public final cardView:Landroidx/cardview/widget/CardView;

.field public final picture:Landroid/widget/ImageView;

.field public final prodName:Landroid/widget/TextView;

.field public final prodPrice:Landroid/widget/TextView;

.field public final productCount:Landroid/widget/TextView;


# direct methods
.method protected constructor <init>(Ljava/lang/Object;Landroid/view/View;ILandroidx/cardview/widget/CardView;Landroid/widget/ImageView;Landroid/widget/TextView;Landroid/widget/TextView;Landroid/widget/TextView;)V
    .locals 0
    .param p1, "_bindingComponent"    # Ljava/lang/Object;
    .param p2, "_root"    # Landroid/view/View;
    .param p3, "_localFieldCount"    # I
    .param p4, "cardView"    # Landroidx/cardview/widget/CardView;
    .param p5, "picture"    # Landroid/widget/ImageView;
    .param p6, "prodName"    # Landroid/widget/TextView;
    .param p7, "prodPrice"    # Landroid/widget/TextView;
    .param p8, "productCount"    # Landroid/widget/TextView;

    .line 37
    invoke-direct {p0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;-><init>(Ljava/lang/Object;Landroid/view/View;I)V

    .line 38
    iput-object p4, p0, Lcom/insecureshop/databinding/CartItemBinding;->cardView:Landroidx/cardview/widget/CardView;

    .line 39
    iput-object p5, p0, Lcom/insecureshop/databinding/CartItemBinding;->picture:Landroid/widget/ImageView;

    .line 40
    iput-object p6, p0, Lcom/insecureshop/databinding/CartItemBinding;->prodName:Landroid/widget/TextView;

    .line 41
    iput-object p7, p0, Lcom/insecureshop/databinding/CartItemBinding;->prodPrice:Landroid/widget/TextView;

    .line 42
    iput-object p8, p0, Lcom/insecureshop/databinding/CartItemBinding;->productCount:Landroid/widget/TextView;

    .line 43
    return-void
.end method

.method public static bind(Landroid/view/View;)Lcom/insecureshop/databinding/CartItemBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;

    .line 85
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/CartItemBinding;->bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/CartItemBinding;

    move-result-object v0

    return-object v0
.end method

.method public static bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/CartItemBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 97
    const v0, 0x7f0c0027

    invoke-static {p1, p0, v0}, Lcom/insecureshop/databinding/CartItemBinding;->bind(Ljava/lang/Object;Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/CartItemBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;)Lcom/insecureshop/databinding/CartItemBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;

    .line 67
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/CartItemBinding;->inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/CartItemBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Z)Lcom/insecureshop/databinding/CartItemBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z

    .line 48
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, p1, p2, v0}, Lcom/insecureshop/databinding/CartItemBinding;->inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/CartItemBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/CartItemBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z
    .param p3, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 62
    const v0, 0x7f0c0027

    invoke-static {p0, v0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/CartItemBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/CartItemBinding;
    .locals 3
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 81
    const v0, 0x7f0c0027

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-static {p0, v0, v1, v2, p1}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/CartItemBinding;

    return-object v0
.end method
