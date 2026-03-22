.class public Lcom/insecureshop/databinding/ToolbarBindingImpl;
.super Lcom/insecureshop/databinding/ToolbarBinding;
.source "ToolbarBindingImpl.java"


# static fields
.field private static final sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

.field private static final sViewsWithIds:Landroid/util/SparseIntArray;


# instance fields
.field private mDirtyFlags:J


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 15
    const/4 v0, 0x0

    sput-object v0, Lcom/insecureshop/databinding/ToolbarBindingImpl;->sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

    .line 16
    new-instance v0, Landroid/util/SparseIntArray;

    invoke-direct {v0}, Landroid/util/SparseIntArray;-><init>()V

    sput-object v0, Lcom/insecureshop/databinding/ToolbarBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    .line 17
    const v1, 0x7f090134

    const/4 v2, 0x1

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 18
    return-void
.end method

.method public constructor <init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V
    .locals 3
    .param p1, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "root"    # Landroid/view/View;

    .line 26
    sget-object v0, Lcom/insecureshop/databinding/ToolbarBindingImpl;->sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

    sget-object v1, Lcom/insecureshop/databinding/ToolbarBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const/4 v2, 0x2

    invoke-static {p1, p2, v2, v0, v1}, Lcom/insecureshop/databinding/ToolbarBindingImpl;->mapBindings(Landroidx/databinding/DataBindingComponent;Landroid/view/View;ILandroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;)[Ljava/lang/Object;

    move-result-object v0

    invoke-direct {p0, p1, p2, v0}, Lcom/insecureshop/databinding/ToolbarBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;)V

    .line 27
    return-void
.end method

.method private constructor <init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;)V
    .locals 7
    .param p1, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "root"    # Landroid/view/View;
    .param p3, "bindings"    # [Ljava/lang/Object;

    .line 29
    const/4 v0, 0x1

    aget-object v0, p3, v0

    move-object v5, v0

    check-cast v5, Landroid/widget/TextView;

    const/4 v0, 0x0

    aget-object v0, p3, v0

    move-object v6, v0

    check-cast v6, Landroidx/appcompat/widget/Toolbar;

    const/4 v4, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    invoke-direct/range {v1 .. v6}, Lcom/insecureshop/databinding/ToolbarBinding;-><init>(Ljava/lang/Object;Landroid/view/View;ILandroid/widget/TextView;Landroidx/appcompat/widget/Toolbar;)V

    .line 82
    const-wide/16 v0, -0x1

    iput-wide v0, p0, Lcom/insecureshop/databinding/ToolbarBindingImpl;->mDirtyFlags:J

    .line 33
    iget-object v0, p0, Lcom/insecureshop/databinding/ToolbarBindingImpl;->toolbar:Landroidx/appcompat/widget/Toolbar;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/appcompat/widget/Toolbar;->setTag(Ljava/lang/Object;)V

    .line 34
    invoke-virtual {p0, p2}, Lcom/insecureshop/databinding/ToolbarBindingImpl;->setRootTag(Landroid/view/View;)V

    .line 36
    invoke-virtual {p0}, Lcom/insecureshop/databinding/ToolbarBindingImpl;->invalidateAll()V

    .line 37
    return-void
.end method


# virtual methods
.method protected executeBindings()V
    .locals 4

    .line 72
    const-wide/16 v0, 0x0

    .line 73
    .local v0, "dirtyFlags":J
    monitor-enter p0

    .line 74
    :try_start_0
    iget-wide v2, p0, Lcom/insecureshop/databinding/ToolbarBindingImpl;->mDirtyFlags:J

    move-wide v0, v2

    .line 75
    const-wide/16 v2, 0x0

    iput-wide v2, p0, Lcom/insecureshop/databinding/ToolbarBindingImpl;->mDirtyFlags:J

    .line 76
    monitor-exit p0

    .line 78
    return-void

    .line 76
    :catchall_0
    move-exception v2

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v2
.end method

.method public hasPendingBindings()Z
    .locals 5

    .line 49
    monitor-enter p0

    .line 50
    :try_start_0
    iget-wide v0, p0, Lcom/insecureshop/databinding/ToolbarBindingImpl;->mDirtyFlags:J

    const-wide/16 v2, 0x0

    cmp-long v4, v0, v2

    if-eqz v4, :cond_0

    .line 51
    const/4 v0, 0x1

    monitor-exit p0

    return v0

    .line 53
    :cond_0
    monitor-exit p0

    .line 54
    const/4 v0, 0x0

    return v0

    .line 53
    :catchall_0
    move-exception v0

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public invalidateAll()V
    .locals 2

    .line 41
    monitor-enter p0

    .line 42
    const-wide/16 v0, 0x1

    :try_start_0
    iput-wide v0, p0, Lcom/insecureshop/databinding/ToolbarBindingImpl;->mDirtyFlags:J

    .line 43
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    invoke-virtual {p0}, Lcom/insecureshop/databinding/ToolbarBindingImpl;->requestRebind()V

    .line 45
    return-void

    .line 43
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

    .line 65
    nop

    .line 67
    const/4 v0, 0x0

    return v0
.end method

.method public setVariable(ILjava/lang/Object;)Z
    .locals 1
    .param p1, "variableId"    # I
    .param p2, "variable"    # Ljava/lang/Object;

    .line 59
    const/4 v0, 0x1

    .line 60
    .local v0, "variableSet":Z
    return v0
.end method
