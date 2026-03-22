.class final Lcom/insecureshop/ProductAdapter$onBindViewHolder$1;
.super Ljava/lang/Object;
.source "ProductAdapter.kt"

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/insecureshop/ProductAdapter;->onBindViewHolder(Lcom/insecureshop/ProductAdapter$ProductViewHolder;I)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x18
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    bv = {
        0x1,
        0x0,
        0x3
    }
    d1 = {
        "\u0000\u0010\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0000\u001a\u00020\u00012\u000e\u0010\u0002\u001a\n \u0004*\u0004\u0018\u00010\u00030\u0003H\n\u00a2\u0006\u0002\u0008\u0005"
    }
    d2 = {
        "<anonymous>",
        "",
        "it",
        "Landroid/view/View;",
        "kotlin.jvm.PlatformType",
        "onClick"
    }
    k = 0x3
    mv = {
        0x1,
        0x1,
        0x10
    }
.end annotation


# instance fields
.field final synthetic $context:Landroid/content/Context;

.field final synthetic $holder:Lcom/insecureshop/ProductAdapter$ProductViewHolder;

.field final synthetic $prodDetail:Lcom/insecureshop/ProductDetail;


# direct methods
.method constructor <init>(Lcom/insecureshop/ProductDetail;Lcom/insecureshop/ProductAdapter$ProductViewHolder;Landroid/content/Context;)V
    .locals 0

    iput-object p1, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$1;->$prodDetail:Lcom/insecureshop/ProductDetail;

    iput-object p2, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$1;->$holder:Lcom/insecureshop/ProductAdapter$ProductViewHolder;

    iput-object p3, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$1;->$context:Landroid/content/Context;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 3
    .param p1, "it"    # Landroid/view/View;

    .line 39
    iget-object v0, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$1;->$prodDetail:Lcom/insecureshop/ProductDetail;

    invoke-virtual {v0}, Lcom/insecureshop/ProductDetail;->getQty()I

    move-result v1

    add-int/lit8 v1, v1, 0x1

    invoke-virtual {v0, v1}, Lcom/insecureshop/ProductDetail;->setQty(I)V

    .line 40
    iget-object v0, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$1;->$holder:Lcom/insecureshop/ProductAdapter$ProductViewHolder;

    invoke-virtual {v0}, Lcom/insecureshop/ProductAdapter$ProductViewHolder;->getMBinding()Lcom/insecureshop/databinding/ProductItemBinding;

    move-result-object v0

    iget-object v0, v0, Lcom/insecureshop/databinding/ProductItemBinding;->productCount:Landroid/widget/TextView;

    const-string v1, "holder.mBinding.productCount"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$1;->$prodDetail:Lcom/insecureshop/ProductDetail;

    invoke-virtual {v1}, Lcom/insecureshop/ProductDetail;->getQty()I

    move-result v1

    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    check-cast v1, Ljava/lang/CharSequence;

    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 41
    sget-object v0, Lcom/insecureshop/util/Util;->INSTANCE:Lcom/insecureshop/util/Util;

    iget-object v1, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$1;->$context:Landroid/content/Context;

    const-string v2, "context"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$1;->$prodDetail:Lcom/insecureshop/ProductDetail;

    invoke-virtual {v0, v1, v2}, Lcom/insecureshop/util/Util;->updateProductItem(Landroid/content/Context;Lcom/insecureshop/ProductDetail;)V

    .line 42
    return-void
.end method
