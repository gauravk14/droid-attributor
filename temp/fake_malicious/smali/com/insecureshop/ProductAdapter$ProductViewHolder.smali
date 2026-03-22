.class public final Lcom/insecureshop/ProductAdapter$ProductViewHolder;
.super Landroidx/recyclerview/widget/RecyclerView$ViewHolder;
.source "ProductAdapter.kt"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/insecureshop/ProductAdapter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ProductViewHolder"
.end annotation

.annotation runtime Lkotlin/Metadata;
    bv = {
        0x1,
        0x0,
        0x3
    }
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0004R\u001a\u0010\u0005\u001a\u00020\u0003X\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007\"\u0004\u0008\u0008\u0010\u0004\u00a8\u0006\t"
    }
    d2 = {
        "Lcom/insecureshop/ProductAdapter$ProductViewHolder;",
        "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;",
        "binding",
        "Lcom/insecureshop/databinding/ProductItemBinding;",
        "(Lcom/insecureshop/databinding/ProductItemBinding;)V",
        "mBinding",
        "getMBinding",
        "()Lcom/insecureshop/databinding/ProductItemBinding;",
        "setMBinding",
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
.field private mBinding:Lcom/insecureshop/databinding/ProductItemBinding;


# direct methods
.method public constructor <init>(Lcom/insecureshop/databinding/ProductItemBinding;)V
    .locals 1
    .param p1, "binding"    # Lcom/insecureshop/databinding/ProductItemBinding;

    const-string v0, "binding"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    invoke-virtual {p1}, Lcom/insecureshop/databinding/ProductItemBinding;->getRoot()Landroid/view/View;

    move-result-object v0

    invoke-direct {p0, v0}, Landroidx/recyclerview/widget/RecyclerView$ViewHolder;-><init>(Landroid/view/View;)V

    .line 17
    iput-object p1, p0, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->mBinding:Lcom/insecureshop/databinding/ProductItemBinding;

    return-void
.end method


# virtual methods
.method public final getMBinding()Lcom/insecureshop/databinding/ProductItemBinding;
    .locals 1

    .line 17
    iget-object v0, p0, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->mBinding:Lcom/insecureshop/databinding/ProductItemBinding;

    return-object v0
.end method

.method public final setMBinding(Lcom/insecureshop/databinding/ProductItemBinding;)V
    .locals 1
    .param p1, "<set-?>"    # Lcom/insecureshop/databinding/ProductItemBinding;

    const-string v0, "<set-?>"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    iput-object p1, p0, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->mBinding:Lcom/insecureshop/databinding/ProductItemBinding;

    return-void
.end method
