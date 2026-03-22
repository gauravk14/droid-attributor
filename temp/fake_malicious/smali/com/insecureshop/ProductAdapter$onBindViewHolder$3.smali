.class final Lcom/insecureshop/ProductAdapter$onBindViewHolder$3;
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

.field final synthetic $prodDetail:Lcom/insecureshop/ProductDetail;


# direct methods
.method constructor <init>(Lcom/insecureshop/ProductDetail;Landroid/content/Context;)V
    .locals 0

    iput-object p1, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$3;->$prodDetail:Lcom/insecureshop/ProductDetail;

    iput-object p2, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$3;->$context:Landroid/content/Context;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 3
    .param p1, "it"    # Landroid/view/View;

    .line 52
    new-instance v0, Landroid/content/Intent;

    const-string v1, "com.insecureshop.action.PRODUCT_DETAIL"

    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 53
    .local v0, "intent":Landroid/content/Intent;
    iget-object v1, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$3;->$prodDetail:Lcom/insecureshop/ProductDetail;

    invoke-virtual {v1}, Lcom/insecureshop/ProductDetail;->getUrl()Ljava/lang/String;

    move-result-object v1

    const-string v2, "url"

    invoke-virtual {v0, v2, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 54
    iget-object v1, p0, Lcom/insecureshop/ProductAdapter$onBindViewHolder$3;->$context:Landroid/content/Context;

    invoke-virtual {v1, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    .line 56
    .end local v0    # "intent":Landroid/content/Intent;
    return-void
.end method
