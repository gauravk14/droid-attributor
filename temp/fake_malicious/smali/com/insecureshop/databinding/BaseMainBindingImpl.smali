.class public Lcom/insecureshop/databinding/BaseMainBindingImpl;
.super Lcom/insecureshop/databinding/BaseMainBinding;
.source "BaseMainBindingImpl.java"


# static fields
.field private static final sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

.field private static final sViewsWithIds:Landroid/util/SparseIntArray;


# instance fields
.field private mDirtyFlags:J

.field private final mboundView0:Landroid/widget/LinearLayout;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 15
    new-instance v0, Landroidx/databinding/ViewDataBinding$IncludedLayouts;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Landroidx/databinding/ViewDataBinding$IncludedLayouts;-><init>(I)V

    sput-object v0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

    .line 16
    const/4 v1, 0x1

    new-array v2, v1, [Ljava/lang/String;

    const-string v3, "toolbar"

    const/4 v4, 0x0

    aput-object v3, v2, v4

    new-array v3, v1, [I

    const/4 v5, 0x2

    aput v5, v3, v4

    new-array v5, v1, [I

    const v6, 0x7f0c0075

    aput v6, v5, v4

    invoke-virtual {v0, v1, v2, v3, v5}, Landroidx/databinding/ViewDataBinding$IncludedLayouts;->setIncludes(I[Ljava/lang/String;[I[I)V

    .line 20
    new-instance v0, Landroid/util/SparseIntArray;

    invoke-direct {v0}, Landroid/util/SparseIntArray;-><init>()V

    sput-object v0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    .line 21
    const v1, 0x7f090060

    const/4 v2, 0x3

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 22
    return-void
.end method

.method public constructor <init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V
    .locals 3
    .param p1, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "root"    # Landroid/view/View;

    .line 32
    sget-object v0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

    sget-object v1, Lcom/insecureshop/databinding/BaseMainBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const/4 v2, 0x4

    invoke-static {p1, p2, v2, v0, v1}, Lcom/insecureshop/databinding/BaseMainBindingImpl;->mapBindings(Landroidx/databinding/DataBindingComponent;Landroid/view/View;ILandroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;)[Ljava/lang/Object;

    move-result-object v0

    invoke-direct {p0, p1, p2, v0}, Lcom/insecureshop/databinding/BaseMainBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;)V

    .line 33
    return-void
.end method

.method private constructor <init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;)V
    .locals 8
    .param p1, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "root"    # Landroid/view/View;
    .param p3, "bindings"    # [Ljava/lang/Object;

    .line 35
    const/4 v0, 0x3

    aget-object v0, p3, v0

    move-object v5, v0

    check-cast v5, Landroid/widget/FrameLayout;

    const/4 v0, 0x1

    aget-object v0, p3, v0

    move-object v6, v0

    check-cast v6, Landroid/widget/LinearLayout;

    const/4 v0, 0x2

    aget-object v0, p3, v0

    move-object v7, v0

    check-cast v7, Lcom/insecureshop/databinding/ToolbarBinding;

    const/4 v4, 0x1

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    invoke-direct/range {v1 .. v7}, Lcom/insecureshop/databinding/BaseMainBinding;-><init>(Ljava/lang/Object;Landroid/view/View;ILandroid/widget/FrameLayout;Landroid/widget/LinearLayout;Lcom/insecureshop/databinding/ToolbarBinding;)V

    .line 113
    const-wide/16 v0, -0x1

    iput-wide v0, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->mDirtyFlags:J

    .line 40
    iget-object v0, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->linToolbar:Landroid/widget/LinearLayout;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/widget/LinearLayout;->setTag(Ljava/lang/Object;)V

    .line 41
    const/4 v0, 0x0

    aget-object v0, p3, v0

    check-cast v0, Landroid/widget/LinearLayout;

    iput-object v0, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->mboundView0:Landroid/widget/LinearLayout;

    .line 42
    invoke-virtual {v0, v1}, Landroid/widget/LinearLayout;->setTag(Ljava/lang/Object;)V

    .line 43
    invoke-virtual {p0, p2}, Lcom/insecureshop/databinding/BaseMainBindingImpl;->setRootTag(Landroid/view/View;)V

    .line 45
    invoke-virtual {p0}, Lcom/insecureshop/databinding/BaseMainBindingImpl;->invalidateAll()V

    .line 46
    return-void
.end method

.method private onChangeToolbar(Lcom/insecureshop/databinding/ToolbarBinding;I)Z
    .locals 4
    .param p1, "Toolbar"    # Lcom/insecureshop/databinding/ToolbarBinding;
    .param p2, "fieldId"    # I

    .line 91
    if-nez p2, :cond_0

    .line 92
    monitor-enter p0

    .line 93
    :try_start_0
    iget-wide v0, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->mDirtyFlags:J

    const-wide/16 v2, 0x1

    or-long/2addr v0, v2

    iput-wide v0, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->mDirtyFlags:J

    .line 94
    monitor-exit p0

    .line 95
    const/4 v0, 0x1

    return v0

    .line 94
    :catchall_0
    move-exception v0

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0

    .line 97
    :cond_0
    const/4 v0, 0x0

    return v0
.end method


# virtual methods
.method protected executeBindings()V
    .locals 4

    .line 102
    const-wide/16 v0, 0x0

    .line 103
    .local v0, "dirtyFlags":J
    monitor-enter p0

    .line 104
    :try_start_0
    iget-wide v2, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->mDirtyFlags:J

    move-wide v0, v2

    .line 105
    const-wide/16 v2, 0x0

    iput-wide v2, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->mDirtyFlags:J

    .line 106
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 108
    iget-object v2, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->toolbar:Lcom/insecureshop/databinding/ToolbarBinding;

    invoke-static {v2}, Lcom/insecureshop/databinding/BaseMainBindingImpl;->executeBindingsOn(Landroidx/databinding/ViewDataBinding;)V

    .line 109
    return-void

    .line 106
    :catchall_0
    move-exception v2

    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v2
.end method

.method public hasPendingBindings()Z
    .locals 6

    .line 59
    monitor-enter p0

    .line 60
    :try_start_0
    iget-wide v0, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->mDirtyFlags:J

    const-wide/16 v2, 0x0

    const/4 v4, 0x1

    cmp-long v5, v0, v2

    if-eqz v5, :cond_0

    .line 61
    monitor-exit p0

    return v4

    .line 63
    :cond_0
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 64
    iget-object v0, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->toolbar:Lcom/insecureshop/databinding/ToolbarBinding;

    invoke-virtual {v0}, Lcom/insecureshop/databinding/ToolbarBinding;->hasPendingBindings()Z

    move-result v0

    if-eqz v0, :cond_1

    .line 65
    return v4

    .line 67
    :cond_1
    const/4 v0, 0x0

    return v0

    .line 63
    :catchall_0
    move-exception v0

    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0
.end method

.method public invalidateAll()V
    .locals 2

    .line 50
    monitor-enter p0

    .line 51
    const-wide/16 v0, 0x2

    :try_start_0
    iput-wide v0, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->mDirtyFlags:J

    .line 52
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    iget-object v0, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->toolbar:Lcom/insecureshop/databinding/ToolbarBinding;

    invoke-virtual {v0}, Lcom/insecureshop/databinding/ToolbarBinding;->invalidateAll()V

    .line 54
    invoke-virtual {p0}, Lcom/insecureshop/databinding/BaseMainBindingImpl;->requestRebind()V

    .line 55
    return-void

    .line 52
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

    .line 84
    if-eqz p1, :cond_0

    .line 88
    const/4 v0, 0x0

    return v0

    .line 86
    :cond_0
    move-object v0, p2

    check-cast v0, Lcom/insecureshop/databinding/ToolbarBinding;

    invoke-direct {p0, v0, p3}, Lcom/insecureshop/databinding/BaseMainBindingImpl;->onChangeToolbar(Lcom/insecureshop/databinding/ToolbarBinding;I)Z

    move-result v0

    return v0
.end method

.method public setLifecycleOwner(Landroidx/lifecycle/LifecycleOwner;)V
    .locals 1
    .param p1, "lifecycleOwner"    # Landroidx/lifecycle/LifecycleOwner;

    .line 78
    invoke-super {p0, p1}, Lcom/insecureshop/databinding/BaseMainBinding;->setLifecycleOwner(Landroidx/lifecycle/LifecycleOwner;)V

    .line 79
    iget-object v0, p0, Lcom/insecureshop/databinding/BaseMainBindingImpl;->toolbar:Lcom/insecureshop/databinding/ToolbarBinding;

    invoke-virtual {v0, p1}, Lcom/insecureshop/databinding/ToolbarBinding;->setLifecycleOwner(Landroidx/lifecycle/LifecycleOwner;)V

    .line 80
    return-void
.end method

.method public setVariable(ILjava/lang/Object;)Z
    .locals 1
    .param p1, "variableId"    # I
    .param p2, "variable"    # Ljava/lang/Object;

    .line 72
    const/4 v0, 0x1

    .line 73
    .local v0, "variableSet":Z
    return v0
.end method
