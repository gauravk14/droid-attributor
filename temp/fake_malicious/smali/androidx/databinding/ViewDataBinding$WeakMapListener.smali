.class Landroidx/databinding/ViewDataBinding$WeakMapListener;
.super Landroidx/databinding/ObservableMap$OnMapChangedCallback;
.source "ViewDataBinding.java"

# interfaces
.implements Landroidx/databinding/ViewDataBinding$ObservableReference;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/databinding/ViewDataBinding;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0xa
    name = "WeakMapListener"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Landroidx/databinding/ObservableMap$OnMapChangedCallback;",
        "Landroidx/databinding/ViewDataBinding$ObservableReference<",
        "Landroidx/databinding/ObservableMap;",
        ">;"
    }
.end annotation


# instance fields
.field final mListener:Landroidx/databinding/ViewDataBinding$WeakListener;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/databinding/ViewDataBinding$WeakListener<",
            "Landroidx/databinding/ObservableMap;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Landroidx/databinding/ViewDataBinding;I)V
    .locals 1
    .param p1, "binder"    # Landroidx/databinding/ViewDataBinding;
    .param p2, "localFieldId"    # I

    .line 1538
    invoke-direct {p0}, Landroidx/databinding/ObservableMap$OnMapChangedCallback;-><init>()V

    .line 1539
    new-instance v0, Landroidx/databinding/ViewDataBinding$WeakListener;

    invoke-direct {v0, p1, p2, p0}, Landroidx/databinding/ViewDataBinding$WeakListener;-><init>(Landroidx/databinding/ViewDataBinding;ILandroidx/databinding/ViewDataBinding$ObservableReference;)V

    iput-object v0, p0, Landroidx/databinding/ViewDataBinding$WeakMapListener;->mListener:Landroidx/databinding/ViewDataBinding$WeakListener;

    .line 1540
    return-void
.end method


# virtual methods
.method public addListener(Landroidx/databinding/ObservableMap;)V
    .locals 0
    .param p1, "target"    # Landroidx/databinding/ObservableMap;

    .line 1553
    invoke-interface {p1, p0}, Landroidx/databinding/ObservableMap;->addOnMapChangedCallback(Landroidx/databinding/ObservableMap$OnMapChangedCallback;)V

    .line 1554
    return-void
.end method

.method public bridge synthetic addListener(Ljava/lang/Object;)V
    .locals 0

    .line 1534
    check-cast p1, Landroidx/databinding/ObservableMap;

    invoke-virtual {p0, p1}, Landroidx/databinding/ViewDataBinding$WeakMapListener;->addListener(Landroidx/databinding/ObservableMap;)V

    return-void
.end method

.method public getListener()Landroidx/databinding/ViewDataBinding$WeakListener;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Landroidx/databinding/ViewDataBinding$WeakListener<",
            "Landroidx/databinding/ObservableMap;",
            ">;"
        }
    .end annotation

    .line 1548
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding$WeakMapListener;->mListener:Landroidx/databinding/ViewDataBinding$WeakListener;

    return-object v0
.end method

.method public onMapChanged(Landroidx/databinding/ObservableMap;Ljava/lang/Object;)V
    .locals 3
    .param p1, "sender"    # Landroidx/databinding/ObservableMap;
    .param p2, "key"    # Ljava/lang/Object;

    .line 1563
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding$WeakMapListener;->mListener:Landroidx/databinding/ViewDataBinding$WeakListener;

    invoke-virtual {v0}, Landroidx/databinding/ViewDataBinding$WeakListener;->getBinder()Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    .line 1564
    .local v0, "binder":Landroidx/databinding/ViewDataBinding;
    if-eqz v0, :cond_1

    iget-object v1, p0, Landroidx/databinding/ViewDataBinding$WeakMapListener;->mListener:Landroidx/databinding/ViewDataBinding$WeakListener;

    invoke-virtual {v1}, Landroidx/databinding/ViewDataBinding$WeakListener;->getTarget()Ljava/lang/Object;

    move-result-object v1

    if-eq p1, v1, :cond_0

    goto :goto_0

    .line 1567
    :cond_0
    iget-object v1, p0, Landroidx/databinding/ViewDataBinding$WeakMapListener;->mListener:Landroidx/databinding/ViewDataBinding$WeakListener;

    iget v1, v1, Landroidx/databinding/ViewDataBinding$WeakListener;->mLocalFieldId:I

    const/4 v2, 0x0

    invoke-static {v0, v1, p1, v2}, Landroidx/databinding/ViewDataBinding;->access$800(Landroidx/databinding/ViewDataBinding;ILjava/lang/Object;I)V

    .line 1568
    return-void

    .line 1565
    :cond_1
    :goto_0
    return-void
.end method

.method public removeListener(Landroidx/databinding/ObservableMap;)V
    .locals 0
    .param p1, "target"    # Landroidx/databinding/ObservableMap;

    .line 1558
    invoke-interface {p1, p0}, Landroidx/databinding/ObservableMap;->removeOnMapChangedCallback(Landroidx/databinding/ObservableMap$OnMapChangedCallback;)V

    .line 1559
    return-void
.end method

.method public bridge synthetic removeListener(Ljava/lang/Object;)V
    .locals 0

    .line 1534
    check-cast p1, Landroidx/databinding/ObservableMap;

    invoke-virtual {p0, p1}, Landroidx/databinding/ViewDataBinding$WeakMapListener;->removeListener(Landroidx/databinding/ObservableMap;)V

    return-void
.end method

.method public setLifecycleOwner(Landroidx/lifecycle/LifecycleOwner;)V
    .locals 0
    .param p1, "lifecycleOwner"    # Landroidx/lifecycle/LifecycleOwner;

    .line 1544
    return-void
.end method
