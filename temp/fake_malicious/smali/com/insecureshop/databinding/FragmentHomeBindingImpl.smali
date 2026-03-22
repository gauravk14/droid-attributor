.class public Lcom/insecureshop/databinding/FragmentHomeBindingImpl;
.super Lcom/insecureshop/databinding/FragmentHomeBinding;
.source "FragmentHomeBindingImpl.java"


# static fields
.field private static final sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

.field private static final sViewsWithIds:Landroid/util/SparseIntArray;


# instance fields
.field private mDirtyFlags:J

.field private final mboundView0:Landroidx/constraintlayout/widget/ConstraintLayout;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 15
    const/4 v0, 0x0

    sput-object v0, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

    .line 16
    sput-object v0, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    .line 17
    return-void
.end method

.method public constructor <init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V
    .locals 3
    .param p1, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "root"    # Landroid/view/View;

    .line 27
    sget-object v0, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

    sget-object v1, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const/4 v2, 0x1

    invoke-static {p1, p2, v2, v0, v1}, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->mapBindings(Landroidx/databinding/DataBindingComponent;Landroid/view/View;ILandroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;)[Ljava/lang/Object;

    move-result-object v0

    invoke-direct {p0, p1, p2, v0}, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;)V

    .line 28
    return-void
.end method

.method private constructor <init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;)V
    .locals 3
    .param p1, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "root"    # Landroid/view/View;
    .param p3, "bindings"    # [Ljava/lang/Object;

    .line 30
    const/4 v0, 0x0

    invoke-direct {p0, p1, p2, v0}, Lcom/insecureshop/databinding/FragmentHomeBinding;-><init>(Ljava/lang/Object;Landroid/view/View;I)V

    .line 82
    const-wide/16 v1, -0x1

    iput-wide v1, p0, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->mDirtyFlags:J

    .line 32
    aget-object v0, p3, v0

    check-cast v0, Landroidx/constraintlayout/widget/ConstraintLayout;

    iput-object v0, p0, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->mboundView0:Landroidx/constraintlayout/widget/ConstraintLayout;

    .line 33
    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/constraintlayout/widget/ConstraintLayout;->setTag(Ljava/lang/Object;)V

    .line 34
    invoke-virtual {p0, p2}, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->setRootTag(Landroid/view/View;)V

    .line 36
    invoke-virtual {p0}, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->invalidateAll()V

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
    iget-wide v2, p0, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->mDirtyFlags:J

    move-wide v0, v2

    .line 75
    const-wide/16 v2, 0x0

    iput-wide v2, p0, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->mDirtyFlags:J

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
    iget-wide v0, p0, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->mDirtyFlags:J

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
    iput-wide v0, p0, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->mDirtyFlags:J

    .line 43
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    invoke-virtual {p0}, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;->requestRebind()V

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
