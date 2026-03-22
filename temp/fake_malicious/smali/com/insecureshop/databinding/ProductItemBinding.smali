.class public abstract Lcom/insecureshop/databinding/ProductItemBinding;
.super Landroidx/databinding/ViewDataBinding;
.source "ProductItemBinding.java"


# instance fields
.field public final cardView:Landroidx/cardview/widget/CardView;

.field public final icAdd:Landroidx/appcompat/widget/AppCompatImageView;

.field public final icRemove:Landroidx/appcompat/widget/AppCompatImageView;

.field public final moreInfo:Landroid/widget/TextView;

.field public final picture:Landroid/widget/ImageView;

.field public final prodName:Landroid/widget/TextView;

.field public final prodPrice:Landroid/widget/TextView;

.field public final productCount:Landroid/widget/TextView;


# direct methods
.method protected constructor <init>(Ljava/lang/Object;Landroid/view/View;ILandroidx/cardview/widget/CardView;Landroidx/appcompat/widget/AppCompatImageView;Landroidx/appcompat/widget/AppCompatImageView;Landroid/widget/TextView;Landroid/widget/ImageView;Landroid/widget/TextView;Landroid/widget/TextView;Landroid/widget/TextView;)V
    .locals 0
    .param p1, "_bindingComponent"    # Ljava/lang/Object;
    .param p2, "_root"    # Landroid/view/View;
    .param p3, "_localFieldCount"    # I
    .param p4, "cardView"    # Landroidx/cardview/widget/CardView;
    .param p5, "icAdd"    # Landroidx/appcompat/widget/AppCompatImageView;
    .param p6, "icRemove"    # Landroidx/appcompat/widget/AppCompatImageView;
    .param p7, "moreInfo"    # Landroid/widget/TextView;
    .param p8, "picture"    # Landroid/widget/ImageView;
    .param p9, "prodName"    # Landroid/widget/TextView;
    .param p10, "prodPrice"    # Landroid/widget/TextView;
    .param p11, "productCount"    # Landroid/widget/TextView;

    .line 47
    invoke-direct {p0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;-><init>(Ljava/lang/Object;Landroid/view/View;I)V

    .line 48
    iput-object p4, p0, Lcom/insecureshop/databinding/ProductItemBinding;->cardView:Landroidx/cardview/widget/CardView;

    .line 49
    iput-object p5, p0, Lcom/insecureshop/databinding/ProductItemBinding;->icAdd:Landroidx/appcompat/widget/AppCompatImageView;

    .line 50
    iput-object p6, p0, Lcom/insecureshop/databinding/ProductItemBinding;->icRemove:Landroidx/appcompat/widget/AppCompatImageView;

    .line 51
    iput-object p7, p0, Lcom/insecureshop/databinding/ProductItemBinding;->moreInfo:Landroid/widget/TextView;

    .line 52
    iput-object p8, p0, Lcom/insecureshop/databinding/ProductItemBinding;->picture:Landroid/widget/ImageView;

    .line 53
    iput-object p9, p0, Lcom/insecureshop/databinding/ProductItemBinding;->prodName:Landroid/widget/TextView;

    .line 54
    iput-object p10, p0, Lcom/insecureshop/databinding/ProductItemBinding;->prodPrice:Landroid/widget/TextView;

    .line 55
    iput-object p11, p0, Lcom/insecureshop/databinding/ProductItemBinding;->productCount:Landroid/widget/TextView;

    .line 56
    return-void
.end method

.method public static bind(Landroid/view/View;)Lcom/insecureshop/databinding/ProductItemBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;

    .line 98
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/ProductItemBinding;->bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v0

    return-object v0
.end method

.method public static bind(Landroid/view/View;Ljava/lang/Object;)Lcom/insecureshop/databinding/ProductItemBinding;
    .locals 1
    .param p0, "view"    # Landroid/view/View;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 110
    const v0, 0x7f0c0064

    invoke-static {p1, p0, v0}, Lcom/insecureshop/databinding/ProductItemBinding;->bind(Ljava/lang/Object;Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/ProductItemBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;)Lcom/insecureshop/databinding/ProductItemBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;

    .line 80
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, v0}, Lcom/insecureshop/databinding/ProductItemBinding;->inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Z)Lcom/insecureshop/databinding/ProductItemBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z

    .line 61
    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-static {p0, p1, p2, v0}, Lcom/insecureshop/databinding/ProductItemBinding;->inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v0

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;ZLjava/lang/Object;)Lcom/insecureshop/databinding/ProductItemBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "root"    # Landroid/view/ViewGroup;
    .param p2, "attachToRoot"    # Z
    .param p3, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 75
    const v0, 0x7f0c0064

    invoke-static {p0, v0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/ProductItemBinding;

    return-object v0
.end method

.method public static inflate(Landroid/view/LayoutInflater;Ljava/lang/Object;)Lcom/insecureshop/databinding/ProductItemBinding;
    .locals 3
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "component"    # Ljava/lang/Object;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 94
    const v0, 0x7f0c0064

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-static {p0, v0, v1, v2, p1}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/databinding/ProductItemBinding;

    return-object v0
.end method
