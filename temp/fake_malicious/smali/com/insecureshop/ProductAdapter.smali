.class public final Lcom/insecureshop/ProductAdapter;
.super Landroidx/recyclerview/widget/RecyclerView$Adapter;
.source "ProductAdapter.kt"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/insecureshop/ProductAdapter$ProductViewHolder;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Landroidx/recyclerview/widget/RecyclerView$Adapter<",
        "Lcom/insecureshop/ProductAdapter$ProductViewHolder;",
        ">;"
    }
.end annotation

.annotation system Ldalvik/annotation/SourceDebugExtension;
    value = "SMAP\nProductAdapter.kt\nKotlin\n*S Kotlin\n*F\n+ 1 ProductAdapter.kt\ncom/insecureshop/ProductAdapter\n*L\n1#1,58:1\n*E\n"
.end annotation

.annotation runtime Lkotlin/Metadata;
    bv = {
        0x1,
        0x0,
        0x3
    }
    d1 = {
        "\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0015B\u0005\u00a2\u0006\u0002\u0010\u0003J\u0008\u0010\u000b\u001a\u00020\u000cH\u0016J\u0018\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u00022\u0006\u0010\u0010\u001a\u00020\u000cH\u0016J\u0018\u0010\u0011\u001a\u00020\u00022\u0006\u0010\u0012\u001a\u00020\u00132\u0006\u0010\u0014\u001a\u00020\u000cH\u0016R \u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00060\u0005X\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0007\u0010\u0008\"\u0004\u0008\t\u0010\n\u00a8\u0006\u0016"
    }
    d2 = {
        "Lcom/insecureshop/ProductAdapter;",
        "Landroidx/recyclerview/widget/RecyclerView$Adapter;",
        "Lcom/insecureshop/ProductAdapter$ProductViewHolder;",
        "()V",
        "productList",
        "",
        "Lcom/insecureshop/ProductDetail;",
        "getProductList",
        "()Ljava/util/List;",
        "setProductList",
        "(Ljava/util/List;)V",
        "getItemCount",
        "",
        "onBindViewHolder",
        "",
        "holder",
        "position",
        "onCreateViewHolder",
        "parent",
        "Landroid/view/ViewGroup;",
        "viewType",
        "ProductViewHolder",
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
.field private productList:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/insecureshop/ProductDetail;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 12
    invoke-direct {p0}, Landroidx/recyclerview/widget/RecyclerView$Adapter;-><init>()V

    .line 14
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    check-cast v0, Ljava/util/List;

    iput-object v0, p0, Lcom/insecureshop/ProductAdapter;->productList:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public getItemCount()I
    .locals 1

    .line 26
    iget-object v0, p0, Lcom/insecureshop/ProductAdapter;->productList:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    return v0
.end method

.method public final getProductList()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/insecureshop/ProductDetail;",
            ">;"
        }
    .end annotation

    .line 14
    iget-object v0, p0, Lcom/insecureshop/ProductAdapter;->productList:Ljava/util/List;

    return-object v0
.end method

.method public bridge synthetic onBindViewHolder(Landroidx/recyclerview/widget/RecyclerView$ViewHolder;I)V
    .locals 0

    .line 12
    check-cast p1, Lcom/insecureshop/ProductAdapter$ProductViewHolder;

    invoke-virtual {p0, p1, p2}, Lcom/insecureshop/ProductAdapter;->onBindViewHolder(Lcom/insecureshop/ProductAdapter$ProductViewHolder;I)V

    return-void
.end method

.method public onBindViewHolder(Lcom/insecureshop/ProductAdapter$ProductViewHolder;I)V
    .locals 5
    .param p1, "holder"    # Lcom/insecureshop/ProductAdapter$ProductViewHolder;
    .param p2, "position"    # I

    const-string v0, "holder"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    iget-object v0, p0, Lcom/insecureshop/ProductAdapter;->productList:Ljava/util/List;

    invoke-interface {v0, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/ProductDetail;

    .line 31
    .local v0, "prodDetail":Lcom/insecureshop/ProductDetail;
    invoke-virtual {p1}, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->getMBinding()Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v1

    invoke-virtual {v1}, Lcom/insecureshop/databinding/ProductItemBinding;->getRoot()Landroid/view/View;

    move-result-object v1

    const-string v2, "holder.mBinding.root"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    .line 32
    .local v1, "context":Landroid/content/Context;
    nop

    .line 34
    nop

    .line 32
    nop

    .line 33
    nop

    .line 32
    invoke-virtual {p1}, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->getMBinding()Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v2

    iget-object v2, v2, Lcom/insecureshop/databinding/ProductItemBinding;->picture:Landroid/widget/ImageView;

    const-string v3, "holder.mBinding.picture"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Landroid/widget/ImageView;->getContext()Landroid/content/Context;

    move-result-object v2

    invoke-static {v2}, Lcom/bumptech/glide/Glide;->with(Landroid/content/Context;)Lcom/bumptech/glide/RequestManager;

    move-result-object v2

    invoke-virtual {v0}, Lcom/insecureshop/ProductDetail;->getImageUrl()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Lcom/bumptech/glide/RequestManager;->load(Ljava/lang/String;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v2

    .line 33
    const/high16 v3, 0x7f0e0000

    invoke-static {v1, v3}, Landroidx/core/content/ContextCompat;->getDrawable(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object v3

    invoke-virtual {v2, v3}, Lcom/bumptech/glide/RequestBuilder;->placeholder(Landroid/graphics/drawable/Drawable;)Lcom/bumptech/glide/request/BaseRequestOptions;

    move-result-object v2

    check-cast v2, Lcom/bumptech/glide/RequestBuilder;

    .line 34
    invoke-virtual {p1}, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->getMBinding()Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v3

    iget-object v3, v3, Lcom/insecureshop/databinding/ProductItemBinding;->picture:Landroid/widget/ImageView;

    invoke-virtual {v2, v3}, Lcom/bumptech/glide/RequestBuilder;->into(Landroid/widget/ImageView;)Lcom/bumptech/glide/request/target/ViewTarget;

    .line 35
    invoke-virtual {p1}, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->getMBinding()Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v2

    iget-object v2, v2, Lcom/insecureshop/databinding/ProductItemBinding;->prodName:Landroid/widget/TextView;

    const-string v3, "holder.mBinding.prodName"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Lcom/insecureshop/ProductDetail;->getName()Ljava/lang/String;

    move-result-object v3

    check-cast v3, Ljava/lang/CharSequence;

    invoke-virtual {v2, v3}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 36
    invoke-virtual {p1}, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->getMBinding()Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v2

    iget-object v2, v2, Lcom/insecureshop/databinding/ProductItemBinding;->productCount:Landroid/widget/TextView;

    const-string v3, "holder.mBinding.productCount"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Lcom/insecureshop/ProductDetail;->getQty()I

    move-result v3

    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v3

    check-cast v3, Ljava/lang/CharSequence;

    invoke-virtual {v2, v3}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 37
    invoke-virtual {p1}, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->getMBinding()Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v2

    iget-object v2, v2, Lcom/insecureshop/databinding/ProductItemBinding;->prodPrice:Landroid/widget/TextView;

    const-string v3, "holder.mBinding.prodPrice"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "$ "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Lcom/insecureshop/ProductDetail;->getPrice()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    check-cast v3, Ljava/lang/CharSequence;

    invoke-virtual {v2, v3}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 38
    invoke-virtual {p1}, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->getMBinding()Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v2

    iget-object v2, v2, Lcom/insecureshop/databinding/ProductItemBinding;->icAdd:Landroidx/appcompat/widget/AppCompatImageView;

    new-instance v3, Lcom/insecureshop/ProductAdapter$onBindViewHolder$1;

    invoke-direct {v3, v0, p1, v1}, Lcom/insecureshop/ProductAdapter$onBindViewHolder$1;-><init>(Lcom/insecureshop/ProductDetail;Lcom/insecureshop/ProductAdapter$ProductViewHolder;Landroid/content/Context;)V

    check-cast v3, Landroid/view/View$OnClickListener;

    invoke-virtual {v2, v3}, Landroidx/appcompat/widget/AppCompatImageView;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 43
    invoke-virtual {p1}, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->getMBinding()Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v2

    iget-object v2, v2, Lcom/insecureshop/databinding/ProductItemBinding;->icRemove:Landroidx/appcompat/widget/AppCompatImageView;

    new-instance v3, Lcom/insecureshop/ProductAdapter$onBindViewHolder$2;

    invoke-direct {v3, v0, p1, v1}, Lcom/insecureshop/ProductAdapter$onBindViewHolder$2;-><init>(Lcom/insecureshop/ProductDetail;Lcom/insecureshop/ProductAdapter$ProductViewHolder;Landroid/content/Context;)V

    check-cast v3, Landroid/view/View$OnClickListener;

    invoke-virtual {v2, v3}, Landroidx/appcompat/widget/AppCompatImageView;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 50
    invoke-virtual {p1}, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->getMBinding()Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v2

    iget-object v2, v2, Lcom/insecureshop/databinding/ProductItemBinding;->moreInfo:Landroid/widget/TextView;

    new-instance v3, Lcom/insecureshop/ProductAdapter$onBindViewHolder$3;

    invoke-direct {v3, v0, v1}, Lcom/insecureshop/ProductAdapter$onBindViewHolder$3;-><init>(Lcom/insecureshop/ProductDetail;Landroid/content/Context;)V

    check-cast v3, Landroid/view/View$OnClickListener;

    invoke-virtual {v2, v3}, Landroid/widget/TextView;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 57
    return-void
.end method

.method public bridge synthetic onCreateViewHolder(Landroid/view/ViewGroup;I)Landroidx/recyclerview/widget/RecyclerView$ViewHolder;
    .locals 0

    .line 12
    invoke-virtual {p0, p1, p2}, Lcom/insecureshop/ProductAdapter;->onCreateViewHolder(Landroid/view/ViewGroup;I)Lcom/insecureshop/ProductAdapter$ProductViewHolder;

    move-result-object p1

    check-cast p1, Landroidx/recyclerview/widget/RecyclerView$ViewHolder;

    return-object p1
.end method

.method public onCreateViewHolder(Landroid/view/ViewGroup;I)Lcom/insecureshop/ProductAdapter$ProductViewHolder;
    .locals 2
    .param p1, "parent"    # Landroid/view/ViewGroup;
    .param p2, "viewType"    # I

    const-string v0, "parent"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    invoke-virtual {p1}, Landroid/view/ViewGroup;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v0

    invoke-static {v0}, Lcom/insecureshop/databinding/ProductItemBinding;->inflate(Landroid/view/LayoutInflater;)Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v0

    const-string v1, "ProductItemBinding.infla\u2026ter.from(parent.context))"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .local v0, "binding":Lcom/insecureshop/databinding/ProductItemBinding;
    new-instance v1, Lcom/insecureshop/ProductAdapter$ProductViewHolder;

    invoke-direct {v1, v0}, Lcom/insecureshop/ProductAdapter$ProductViewHolder;-><init>(Lcom/insecureshop/databinding/ProductItemBinding;)V

    return-object v1
.end method

.method public final setProductList(Ljava/util/List;)V
    .locals 1
    .param p1, "<set-?>"    # Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/insecureshop/ProductDetail;",
            ">;)V"
        }
    .end annotation

    const-string v0, "<set-?>"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    iput-object p1, p0, Lcom/insecureshop/ProductAdapter;->productList:Ljava/util/List;

    return-void
.end method
