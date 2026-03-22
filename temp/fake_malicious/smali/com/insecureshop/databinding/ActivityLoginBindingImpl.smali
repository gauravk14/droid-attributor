.class public Lcom/insecureshop/databinding/ActivityLoginBindingImpl;
.super Lcom/insecureshop/databinding/ActivityLoginBinding;
.source "ActivityLoginBindingImpl.java"


# static fields
.field private static final sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

.field private static final sViewsWithIds:Landroid/util/SparseIntArray;


# instance fields
.field private mDirtyFlags:J

.field private final mboundView0:Landroidx/constraintlayout/widget/ConstraintLayout;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 15
    const/4 v0, 0x0

    sput-object v0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

    .line 16
    new-instance v0, Landroid/util/SparseIntArray;

    invoke-direct {v0}, Landroid/util/SparseIntArray;-><init>()V

    sput-object v0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    .line 17
    const v1, 0x7f09009c

    const/4 v2, 0x1

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 18
    sget-object v0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f09009e

    const/4 v2, 0x2

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 19
    sget-object v0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f090127

    const/4 v2, 0x3

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 20
    sget-object v0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f090077

    const/4 v2, 0x4

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 21
    sget-object v0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f090126

    const/4 v2, 0x5

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 22
    sget-object v0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f090076

    const/4 v2, 0x6

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 23
    sget-object v0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const v1, 0x7f09004b

    const/4 v2, 0x7

    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->put(II)V

    .line 24
    return-void
.end method

.method public constructor <init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V
    .locals 3
    .param p1, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "root"    # Landroid/view/View;

    .line 34
    sget-object v0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->sIncludes:Landroidx/databinding/ViewDataBinding$IncludedLayouts;

    sget-object v1, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->sViewsWithIds:Landroid/util/SparseIntArray;

    const/16 v2, 0x8

    invoke-static {p1, p2, v2, v0, v1}, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->mapBindings(Landroidx/databinding/DataBindingComponent;Landroid/view/View;ILandroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;)[Ljava/lang/Object;

    move-result-object v0

    invoke-direct {p0, p1, p2, v0}, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;)V

    .line 35
    return-void
.end method

.method private constructor <init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;)V
    .locals 12
    .param p1, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "root"    # Landroid/view/View;
    .param p3, "bindings"    # [Ljava/lang/Object;

    .line 37
    const/4 v0, 0x7

    aget-object v0, p3, v0

    move-object v5, v0

    check-cast v5, Landroidx/appcompat/widget/AppCompatButton;

    const/4 v0, 0x6

    aget-object v0, p3, v0

    move-object v6, v0

    check-cast v6, Lcom/google/android/material/textfield/TextInputEditText;

    const/4 v0, 0x4

    aget-object v0, p3, v0

    move-object v7, v0

    check-cast v7, Lcom/google/android/material/textfield/TextInputEditText;

    const/4 v0, 0x1

    aget-object v0, p3, v0

    move-object v8, v0

    check-cast v8, Landroidx/appcompat/widget/AppCompatImageView;

    const/4 v0, 0x2

    aget-object v0, p3, v0

    move-object v9, v0

    check-cast v9, Landroidx/appcompat/widget/AppCompatTextView;

    const/4 v0, 0x5

    aget-object v0, p3, v0

    move-object v10, v0

    check-cast v10, Lcom/google/android/material/textfield/TextInputLayout;

    const/4 v0, 0x3

    aget-object v0, p3, v0

    move-object v11, v0

    check-cast v11, Lcom/google/android/material/textfield/TextInputLayout;

    const/4 v4, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    invoke-direct/range {v1 .. v11}, Lcom/insecureshop/databinding/ActivityLoginBinding;-><init>(Ljava/lang/Object;Landroid/view/View;ILandroidx/appcompat/widget/AppCompatButton;Lcom/google/android/material/textfield/TextInputEditText;Lcom/google/android/material/textfield/TextInputEditText;Landroidx/appcompat/widget/AppCompatImageView;Landroidx/appcompat/widget/AppCompatTextView;Lcom/google/android/material/textfield/TextInputLayout;Lcom/google/android/material/textfield/TextInputLayout;)V

    .line 96
    const-wide/16 v0, -0x1

    iput-wide v0, p0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->mDirtyFlags:J

    .line 46
    const/4 v0, 0x0

    aget-object v0, p3, v0

    check-cast v0, Landroidx/constraintlayout/widget/ConstraintLayout;

    iput-object v0, p0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->mboundView0:Landroidx/constraintlayout/widget/ConstraintLayout;

    .line 47
    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/constraintlayout/widget/ConstraintLayout;->setTag(Ljava/lang/Object;)V

    .line 48
    invoke-virtual {p0, p2}, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->setRootTag(Landroid/view/View;)V

    .line 50
    invoke-virtual {p0}, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->invalidateAll()V

    .line 51
    return-void
.end method


# virtual methods
.method protected executeBindings()V
    .locals 4

    .line 86
    const-wide/16 v0, 0x0

    .line 87
    .local v0, "dirtyFlags":J
    monitor-enter p0

    .line 88
    :try_start_0
    iget-wide v2, p0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->mDirtyFlags:J

    move-wide v0, v2

    .line 89
    const-wide/16 v2, 0x0

    iput-wide v2, p0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->mDirtyFlags:J

    .line 90
    monitor-exit p0

    .line 92
    return-void

    .line 90
    :catchall_0
    move-exception v2

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v2
.end method

.method public hasPendingBindings()Z
    .locals 5

    .line 63
    monitor-enter p0

    .line 64
    :try_start_0
    iget-wide v0, p0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->mDirtyFlags:J

    const-wide/16 v2, 0x0

    cmp-long v4, v0, v2

    if-eqz v4, :cond_0

    .line 65
    const/4 v0, 0x1

    monitor-exit p0

    return v0

    .line 67
    :cond_0
    monitor-exit p0

    .line 68
    const/4 v0, 0x0

    return v0

    .line 67
    :catchall_0
    move-exception v0

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public invalidateAll()V
    .locals 2

    .line 55
    monitor-enter p0

    .line 56
    const-wide/16 v0, 0x1

    :try_start_0
    iput-wide v0, p0, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->mDirtyFlags:J

    .line 57
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 58
    invoke-virtual {p0}, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;->requestRebind()V

    .line 59
    return-void

    .line 57
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

    .line 79
    nop

    .line 81
    const/4 v0, 0x0

    return v0
.end method

.method public setVariable(ILjava/lang/Object;)Z
    .locals 1
    .param p1, "variableId"    # I
    .param p2, "variable"    # Ljava/lang/Object;

    .line 73
    const/4 v0, 0x1

    .line 74
    .local v0, "variableSet":Z
    return v0
.end method
