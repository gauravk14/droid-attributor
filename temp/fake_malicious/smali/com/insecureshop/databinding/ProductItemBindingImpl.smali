.class public Lcom/insecureshop/databinding/ProductItemBindingImpl;
.super Lcom/insecureshop/databinding/ProductItemBinding;
.source "ProductItemBindingImpl.java"


# static fields
.field private static final sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

.field private static final sViewsWithIds:Landroid/util/SparseIntArray;


# instance fields
.field private mDirtyFlags:J

.field private final mboundView0:Landroid/widget/RelativeLayout;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 15
    const/4 v0, 0x0

    sput-object v0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

    .line 16
    new-instance v0, Landroid/util/SparseIntArray;

    invoke-direct {v0}, Landroid/util/SparseIntArray;-><init>()V

    sput-object v0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    .line 17
    const v1, 0x7f090050

    const/4 v2, 0x1

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 18
    sget-object v0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f0900dd

    const/4 v2, 0x2

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 19
    sget-object v0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f0900df

    const/4 v2, 0x3

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 20
    sget-object v0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f0900b2

    const/4 v2, 0x4

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 21
    sget-object v0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f0900e0

    const/4 v2, 0x5

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 22
    sget-object v0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f090091

    const/4 v2, 0x6

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 23
    sget-object v0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f0900e1

    const/4 v2, 0x7

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 24
    sget-object v0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f090092

    const/16 v2, 0x8

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 25
    return-void
.end method

.method public constructor <init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V
    .locals 3
    .param p1, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "root"    # Landroid/view/View;

    .line 35
    sget-object v0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

    sget-object v1, Lcom/insecureshop/databinding/ProductItemBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const/16 v2, 0x9

    invoke-static {p1, p2, v2, v0, v1}, Lcom/insecureshop/databinding/ProductItemBindingImpl;->mapBindings(Landroidx/databinding/DataBindingComponent;Landroid/view/View;ILandroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;)[Ljava/lang/Object;

    move-result-object v0

    invoke-direct {p0, p1, p2, v0}, Lcom/insecureshop/databinding/ProductItemBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;)V

    .line 36
    return-void
.end method

.method private constructor <init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;)V
    .locals 13
    .param p1, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "root"    # Landroid/view/View;
    .param p3, "bindings"    # [Ljava/lang/Object;

    .line 38
    move-object v12, p0

    const/4 v0, 0x1

    aget-object v0, p3, v0

    move-object v4, v0

    check-cast v4, Landroidx/cardview/widget/CardView;

    const/4 v0, 0x6

    aget-object v0, p3, v0

    move-object v5, v0

    check-cast v5, Landroidx/appcompat/widget/AppCompatImageView;

    const/16 v0, 0x8

    aget-object v0, p3, v0

    move-object v6, v0

    check-cast v6, Landroidx/appcompat/widget/AppCompatImageView;

    const/4 v0, 0x4

    aget-object v0, p3, v0

    move-object v7, v0

    check-cast v7, Landroid/widget/TextView;

    const/4 v0, 0x2

    aget-object v0, p3, v0

    move-object v8, v0

    check-cast v8, Landroid/widget/ImageView;

    const/4 v0, 0x3

    aget-object v0, p3, v0

    move-object v9, v0

    check-cast v9, Landroid/widget/TextView;

    const/4 v0, 0x5

    aget-object v0, p3, v0

    move-object v10, v0

    check-cast v10, Landroid/widget/TextView;

    const/4 v0, 0x7

    aget-object v0, p3, v0

    move-object v11, v0

    check-cast v11, Landroid/widget/TextView;

    const/4 v3, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    invoke-direct/range {v0 .. v11}, Lcom/insecureshop/databinding/ProductItemBinding;-><init>(Ljava/lang/Object;Landroid/view/View;ILandroidx/cardview/widget/CardView;Landroidx/appcompat/widget/AppCompatImageView;Landroidx/appcompat/widget/AppCompatImageView;Landroid/widget/TextView;Landroid/widget/ImageView;Landroid/widget/TextView;Landroid/widget/TextView;Landroid/widget/TextView;)V

    .line 98
    const-wide/16 v0, -0x1

    iput-wide v0, v12, Lcom/insecureshop/databinding/ProductItemBindingImpl;->mDirtyFlags:J

    .line 48
    const/4 v0, 0x0

    aget-object v0, p3, v0

    check-cast v0, Landroid/widget/RelativeLayout;

    iput-object v0, v12, Lcom/insecureshop/databinding/ProductItemBindingImpl;->mboundView0:Landroid/widget/RelativeLayout;

    .line 49
    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/widget/RelativeLayout;->setTag(Ljava/lang/Object;)V

    .line 50
    move-object v0, p2

    invoke-virtual {p0, p2}, Lcom/insecureshop/databinding/ProductItemBindingImpl;->setRootTag(Landroid/view/View;)V

    .line 52
    invoke-virtual {p0}, Lcom/insecureshop/databinding/ProductItemBindingImpl;->invalidateAll()V

    .line 53
    return-void
.end method


# virtual methods
.method protected executeBindings()V
    .locals 4

    .line 88
    const-wide/16 v0, 0x0

    .line 89
    .local v0, "dirtyFlags":J
    monitor-enter p0

    .line 90
    :try_start_0
    iget-wide v2, p0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->mDirtyFlags:J

    move-wide v0, v2

    .line 91
    const-wide/16 v2, 0x0

    iput-wide v2, p0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->mDirtyFlags:J

    .line 92
    monitor-exit p0

    .line 94
    return-void

    .line 92
    :catchall_0
    move-exception v2

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v2
.end method

.method public hasPendingBindings()Z
    .locals 5

    .line 65
    monitor-enter p0

    .line 66
    :try_start_0
    iget-wide v0, p0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->mDirtyFlags:J

    const-wide/16 v2, 0x0

    cmp-long v4, v0, v2

    if-eqz v4, :cond_0

    .line 67
    const/4 v0, 0x1

    monitor-exit p0

    return v0

    .line 69
    :cond_0
    monitor-exit p0

    .line 70
    const/4 v0, 0x0

    return v0

    .line 69
    :catchall_0
    move-exception v0

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public invalidateAll()V
    .locals 2

    .line 57
    monitor-enter p0

    .line 58
    const-wide/16 v0, 0x1

    :try_start_0
    iput-wide v0, p0, Lcom/insecureshop/databinding/ProductItemBindingImpl;->mDirtyFlags:J

    .line 59
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 60
    invoke-virtual {p0}, Lcom/insecureshop/databinding/ProductItemBindingImpl;->requestRebind()V

    .line 61
    return-void

    .line 59
    :catchall_0
    move-exception v0

    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0
.end method

.method protected onFieldChange(ILjava/lang/Object;I)Z
    .locals 1
    .param p1, "localFieldId"    # I
    .param p2, "object"    # Ljava/lang/Object;
    .param p3, "fieldId"    # I

    .line 81
    nop

    .line 83
    const/4 v0, 0x0

    return v0
.end method

.method public setVariable(ILjava/lang/Object;)Z
    .locals 1
    .param p1, "variableId"    # I
    .param p2, "variable"    # Ljava/lang/Object;

    .line 75
    const/4 v0, 0x1

    .line 76
    .local v0, "variableSet":Z
    return v0
.end method
