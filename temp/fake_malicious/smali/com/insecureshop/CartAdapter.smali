.class public final Lcom/insecureshop/CartAdapter;
.super Landroidx/recyclerview/widget/RecyclerView$Adapter;
.source "CartAdapter.kt"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/insecureshop/CartAdapter$CartViewHolder;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Landroidx/recyclerview/widget/RecyclerView$Adapter<",
        "Lcom/insecureshop/CartAdapter$CartViewHolder;",
        ">;"
    }
.end annotation

.annotation system Ldalvik/annotation/SourceDebugExtension;
    value = "SMAP\nCartAdapter.kt\nKotlin\n*S Kotlin\n*F\n+ 1 CartAdapter.kt\ncom/insecureshop/CartAdapter\n*L\n1#1,34:1\n*E\n"
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
        "Lcom/insecureshop/CartAdapter;",
        "Landroidx/recyclerview/widget/RecyclerView$Adapter;",
        "Lcom/insecureshop/CartAdapter$CartViewHolder;",
        "()V",
        "cartList",
        "",
        "Lcom/insecureshop/ProductDetail;",
        "getCartList",
        "()Ljava/util/List;",
        "setCartList",
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
        "CartViewHolder",
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
.field private cartList:Ljava/util/List;
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

    .line 9
    invoke-direct {p0}, Landroidx/recyclerview/widget/RecyclerView$Adapter;-><init>()V

    .line 11
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    check-cast v0, Ljava/util/List;

    iput-object v0, p0, Lcom/insecureshop/CartAdapter;->cartList:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final getCartList()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/insecureshop/ProductDetail;",
            ">;"
        }
    .end annotation

    .line 11
    iget-object v0, p0, Lcom/insecureshop/CartAdapter;->cartList:Ljava/util/List;

    return-object v0
.end method

.method public getItemCount()I
    .locals 1

    .line 23
    iget-object v0, p0, Lcom/insecureshop/CartAdapter;->cartList:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    return v0
.end method

.method public bridge synthetic onBindViewHolder(Landroidx/recyclerview/widget/RecyclerView$ViewHolder;I)V
    .locals 0

    .line 9
    check-cast p1, Lcom/insecureshop/CartAdapter$CartViewHolder;

    invoke-virtual {p0, p1, p2}, Lcom/insecureshop/CartAdapter;->onBindViewHolder(Lcom/insecureshop/CartAdapter$CartViewHolder;I)V

    return-void
.end method

.method public onBindViewHolder(Lcom/insecureshop/CartAdapter$CartViewHolder;I)V
    .locals 4
    .param p1, "holder"    # Lcom/insecureshop/CartAdapter$CartViewHolder;
    .param p2, "position"    # I

    const-string v0, "holder"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    iget-object v0, p0, Lcom/insecureshop/CartAdapter;->cartList:Ljava/util/List;

    invoke-interface {v0, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/insecureshop/ProductDetail;

    .line 28
    .local v0, "prodDetail":Lcom/insecureshop/ProductDetail;
    nop

    .line 29
    nop

    .line 28
    invoke-virtual {p1}, Lcom/insecureshop/CartAdapter$CartViewHolder;->getMBinding()Lcom/insecureshop/databinding/CartItemBinding;

    move-result-object v1

    iget-object v1, v1, Lcom/insecureshop/databinding/CartItemBinding;->picture:Landroid/widget/ImageView;

    const-string v2, "holder.mBinding.picture"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Landroid/widget/ImageView;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-static {v1}, Lcom/bumptech/glide/Glide;->with(Landroid/content/Context;)Lcom/bumptech/glide/RequestManager;

    move-result-object v1

    invoke-virtual {v0}, Lcom/insecureshop/ProductDetail;->getImageUrl()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Lcom/bumptech/glide/RequestManager;->load(Ljava/lang/String;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v1

    .line 29
    invoke-virtual {p1}, Lcom/insecureshop/CartAdapter$CartViewHolder;->getMBinding()Lcom/insecureshop/databinding/CartItemBinding;

    move-result-object v2

    iget-object v2, v2, Lcom/insecureshop/databinding/CartItemBinding;->picture:Landroid/widget/ImageView;

    invoke-virtual {v1, v2}, Lcom/bumptech/glide/RequestBuilder;->into(Landroid/widget/ImageView;)Lcom/bumptech/glide/request/target/ViewTarget;

    .line 30
    invoke-virtual {p1}, Lcom/insecureshop/CartAdapter$CartViewHolder;->getMBinding()Lcom/insecureshop/databinding/CartItemBinding;

    move-result-object v1

    iget-object v1, v1, Lcom/insecureshop/databinding/CartItemBinding;->prodName:Landroid/widget/TextView;

    const-string v2, "holder.mBinding.prodName"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Lcom/insecureshop/ProductDetail;->getName()Ljava/lang/String;

    move-result-object v2

    check-cast v2, Ljava/lang/CharSequence;

    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 31
    invoke-virtual {p1}, Lcom/insecureshop/CartAdapter$CartViewHolder;->getMBinding()Lcom/insecureshop/databinding/CartItemBinding;

    move-result-object v1

    iget-object v1, v1, Lcom/insecureshop/databinding/CartItemBinding;->prodPrice:Landroid/widget/TextView;

    const-string v2, "holder.mBinding.prodPrice"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "$ "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Lcom/insecureshop/ProductDetail;->getPrice()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    check-cast v2, Ljava/lang/CharSequence;

    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 32
    invoke-virtual {p1}, Lcom/insecureshop/CartAdapter$CartViewHolder;->getMBinding()Lcom/insecureshop/databinding/CartItemBinding;

    move-result-object v1

    iget-object v1, v1, Lcom/insecureshop/databinding/CartItemBinding;->productCount:Landroid/widget/TextView;

    const-string v2, "holder.mBinding.productCount"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, " Qty : "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Lcom/insecureshop/ProductDetail;->getQty()I

    move-result v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    check-cast v2, Ljava/lang/CharSequence;

    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 33
    return-void
.end method

.method public bridge synthetic onCreateViewHolder(Landroid/view/ViewGroup;I)Landroidx/recyclerview/widget/RecyclerView$ViewHolder;
    .locals 0

    .line 9
    invoke-virtual {p0, p1, p2}, Lcom/insecureshop/CartAdapter;->onCreateViewHolder(Landroid/view/ViewGroup;I)Lcom/insecureshop/CartAdapter$CartViewHolder;

    move-result-object p1

    check-cast p1, Landroidx/recyclerview/widget/RecyclerView$ViewHolder;

    return-object p1
.end method

.method public onCreateViewHolder(Landroid/view/ViewGroup;I)Lcom/insecureshop/CartAdapter$CartViewHolder;
    .locals 2
    .param p1, "parent"    # Landroid/view/ViewGroup;
    .param p2, "viewType"    # I

    const-string v0, "parent"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    invoke-virtual {p1}, Landroid/view/ViewGroup;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v0

    invoke-static {v0}, Lcom/insecureshop/databinding/CartItemBinding;->inflate(Landroid/view/LayoutInflater;)Lcom/insecureshop/databinding/CartItemBinding;

    move-result-object v0

    const-string v1, "CartItemBinding.inflate(\u2026ter.from(parent.context))"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .local v0, "binding":Lcom/insecureshop/databinding/CartItemBinding;
    new-instance v1, Lcom/insecureshop/CartAdapter$CartViewHolder;

    invoke-direct {v1, v0}, Lcom/insecureshop/CartAdapter$CartViewHolder;-><init>(Lcom/insecureshop/databinding/CartItemBinding;)V

    return-object v1
.end method

.method public final setCartList(Ljava/util/List;)V
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

    .line 11
    iput-object p1, p0, Lcom/insecureshop/CartAdapter;->cartList:Ljava/util/List;

    return-void
.end method
