.class public abstract Landroidx/databinding/ViewDataBinding;
.super Landroidx/databinding/BaseObservable;
.source "ViewDataBinding.java"

# interfaces
.implements Landroidx/viewbinding/ViewBinding;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/databinding/ViewDataBinding$OnStartListener;,
        Landroidx/databinding/ViewDataBinding$PropertyChangedInverseListener;,
        Landroidx/databinding/ViewDataBinding$IncludedLayouts;,
        Landroidx/databinding/ViewDataBinding$CreateWeakListener;,
        Landroidx/databinding/ViewDataBinding$LiveDataListener;,
        Landroidx/databinding/ViewDataBinding$WeakMapListener;,
        Landroidx/databinding/ViewDataBinding$WeakListListener;,
        Landroidx/databinding/ViewDataBinding$WeakPropertyListener;,
        Landroidx/databinding/ViewDataBinding$WeakListener;,
        Landroidx/databinding/ViewDataBinding$ObservableReference;
    }
.end annotation


# static fields
.field private static final BINDING_NUMBER_START:I

.field public static final BINDING_TAG_PREFIX:Ljava/lang/String; = "binding_"

.field private static final CREATE_LIST_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

.field private static final CREATE_LIVE_DATA_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

.field private static final CREATE_MAP_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

.field private static final CREATE_PROPERTY_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

.field private static final HALTED:I = 0x2

.field private static final REBIND:I = 0x1

.field private static final REBIND_NOTIFIER:Landroidx/databinding/CallbackRegistry$NotifierCallback;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/databinding/CallbackRegistry$NotifierCallback<",
            "Landroidx/databinding/OnRebindCallback;",
            "Landroidx/databinding/ViewDataBinding;",
            "Ljava/lang/Void;",
            ">;"
        }
    .end annotation
.end field

.field private static final REBOUND:I = 0x3

.field private static final ROOT_REATTACHED_LISTENER:Landroid/view/View$OnAttachStateChangeListener;

.field static SDK_INT:I

.field private static final USE_CHOREOGRAPHER:Z

.field private static final sReferenceQueue:Ljava/lang/ref/ReferenceQueue;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ref/ReferenceQueue<",
            "Landroidx/databinding/ViewDataBinding;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field protected final mBindingComponent:Landroidx/databinding/DataBindingComponent;

.field private mChoreographer:Landroid/view/Choreographer;

.field private mContainingBinding:Landroidx/databinding/ViewDataBinding;

.field private final mFrameCallback:Landroid/view/Choreographer$FrameCallback;

.field private mInLiveDataRegisterObserver:Z

.field private mIsExecutingPendingBindings:Z

.field private mLifecycleOwner:Landroidx/lifecycle/LifecycleOwner;

.field private mLocalFieldObservers:[Landroidx/databinding/ViewDataBinding$WeakListener;

.field private mOnStartListener:Landroidx/databinding/ViewDataBinding$OnStartListener;

.field private mPendingRebind:Z

.field private mRebindCallbacks:Landroidx/databinding/CallbackRegistry;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/databinding/CallbackRegistry<",
            "Landroidx/databinding/OnRebindCallback;",
            "Landroidx/databinding/ViewDataBinding;",
            "Ljava/lang/Void;",
            ">;"
        }
    .end annotation
.end field

.field private mRebindHalted:Z

.field private final mRebindRunnable:Ljava/lang/Runnable;

.field private final mRoot:Landroid/view/View;

.field private mUIThreadHandler:Landroid/os/Handler;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 71
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    sput v0, Landroidx/databinding/ViewDataBinding;->SDK_INT:I

    .line 86
    const-string v0, "binding_"

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    sput v0, Landroidx/databinding/ViewDataBinding;->BINDING_NUMBER_START:I

    .line 88
    sget v0, Landroidx/databinding/ViewDataBinding;->SDK_INT:I

    const/16 v1, 0x10

    if-lt v0, v1, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    sput-boolean v0, Landroidx/databinding/ViewDataBinding;->USE_CHOREOGRAPHER:Z

    .line 93
    new-instance v0, Landroidx/databinding/ViewDataBinding$1;

    invoke-direct {v0}, Landroidx/databinding/ViewDataBinding$1;-><init>()V

    sput-object v0, Landroidx/databinding/ViewDataBinding;->CREATE_PROPERTY_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

    .line 103
    new-instance v0, Landroidx/databinding/ViewDataBinding$2;

    invoke-direct {v0}, Landroidx/databinding/ViewDataBinding$2;-><init>()V

    sput-object v0, Landroidx/databinding/ViewDataBinding;->CREATE_LIST_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

    .line 113
    new-instance v0, Landroidx/databinding/ViewDataBinding$3;

    invoke-direct {v0}, Landroidx/databinding/ViewDataBinding$3;-><init>()V

    sput-object v0, Landroidx/databinding/ViewDataBinding;->CREATE_MAP_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

    .line 123
    new-instance v0, Landroidx/databinding/ViewDataBinding$4;

    invoke-direct {v0}, Landroidx/databinding/ViewDataBinding$4;-><init>()V

    sput-object v0, Landroidx/databinding/ViewDataBinding;->CREATE_LIVE_DATA_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

    .line 131
    new-instance v0, Landroidx/databinding/ViewDataBinding$5;

    invoke-direct {v0}, Landroidx/databinding/ViewDataBinding$5;-><init>()V

    sput-object v0, Landroidx/databinding/ViewDataBinding;->REBIND_NOTIFIER:Landroidx/databinding/CallbackRegistry$NotifierCallback;

    .line 151
    new-instance v0, Ljava/lang/ref/ReferenceQueue;

    invoke-direct {v0}, Ljava/lang/ref/ReferenceQueue;-><init>()V

    sput-object v0, Landroidx/databinding/ViewDataBinding;->sReferenceQueue:Ljava/lang/ref/ReferenceQueue;

    .line 156
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x13

    if-ge v0, v1, :cond_1

    .line 157
    const/4 v0, 0x0

    sput-object v0, Landroidx/databinding/ViewDataBinding;->ROOT_REATTACHED_LISTENER:Landroid/view/View$OnAttachStateChangeListener;

    goto :goto_1

    .line 159
    :cond_1
    new-instance v0, Landroidx/databinding/ViewDataBinding$6;

    invoke-direct {v0}, Landroidx/databinding/ViewDataBinding$6;-><init>()V

    sput-object v0, Landroidx/databinding/ViewDataBinding;->ROOT_REATTACHED_LISTENER:Landroid/view/View$OnAttachStateChangeListener;

    .line 174
    :goto_1
    return-void
.end method

.method protected constructor <init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;I)V
    .locals 2
    .param p1, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "root"    # Landroid/view/View;
    .param p3, "localFieldCount"    # I

    .line 279
    invoke-direct {p0}, Landroidx/databinding/BaseObservable;-><init>()V

    .line 179
    new-instance v0, Landroidx/databinding/ViewDataBinding$7;

    invoke-direct {v0, p0}, Landroidx/databinding/ViewDataBinding$7;-><init>(Landroidx/databinding/ViewDataBinding;)V

    iput-object v0, p0, Landroidx/databinding/ViewDataBinding;->mRebindRunnable:Ljava/lang/Runnable;

    .line 204
    const/4 v0, 0x0

    iput-boolean v0, p0, Landroidx/databinding/ViewDataBinding;->mPendingRebind:Z

    .line 209
    iput-boolean v0, p0, Landroidx/databinding/ViewDataBinding;->mRebindHalted:Z

    .line 280
    iput-object p1, p0, Landroidx/databinding/ViewDataBinding;->mBindingComponent:Landroidx/databinding/DataBindingComponent;

    .line 281
    new-array v0, p3, [Landroidx/databinding/ViewDataBinding$WeakListener;

    iput-object v0, p0, Landroidx/databinding/ViewDataBinding;->mLocalFieldObservers:[Landroidx/databinding/ViewDataBinding$WeakListener;

    .line 282
    iput-object p2, p0, Landroidx/databinding/ViewDataBinding;->mRoot:Landroid/view/View;

    .line 283
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 286
    sget-boolean v0, Landroidx/databinding/ViewDataBinding;->USE_CHOREOGRAPHER:Z

    if-eqz v0, :cond_0

    .line 287
    invoke-static {}, Landroid/view/Choreographer;->getInstance()Landroid/view/Choreographer;

    move-result-object v0

    iput-object v0, p0, Landroidx/databinding/ViewDataBinding;->mChoreographer:Landroid/view/Choreographer;

    .line 288
    new-instance v0, Landroidx/databinding/ViewDataBinding$8;

    invoke-direct {v0, p0}, Landroidx/databinding/ViewDataBinding$8;-><init>(Landroidx/databinding/ViewDataBinding;)V

    iput-object v0, p0, Landroidx/databinding/ViewDataBinding;->mFrameCallback:Landroid/view/Choreographer$FrameCallback;

    goto :goto_0

    .line 295
    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Landroidx/databinding/ViewDataBinding;->mFrameCallback:Landroid/view/Choreographer$FrameCallback;

    .line 296
    new-instance v0, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object v1

    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    iput-object v0, p0, Landroidx/databinding/ViewDataBinding;->mUIThreadHandler:Landroid/os/Handler;

    .line 298
    :goto_0
    return-void

    .line 284
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "DataBinding must be created in view\'s UI Thread"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method protected constructor <init>(Ljava/lang/Object;Landroid/view/View;I)V
    .locals 1
    .param p1, "bindingComponent"    # Ljava/lang/Object;
    .param p2, "root"    # Landroid/view/View;
    .param p3, "localFieldCount"    # I

    .line 304
    invoke-static {p1}, Landroidx/databinding/ViewDataBinding;->checkAndCastToBindingComponent(Ljava/lang/Object;)Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    invoke-direct {p0, v0, p2, p3}, Landroidx/databinding/ViewDataBinding;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;I)V

    .line 305
    return-void
.end method

.method static synthetic access$002(Landroidx/databinding/ViewDataBinding;Z)Z
    .locals 0
    .param p0, "x0"    # Landroidx/databinding/ViewDataBinding;
    .param p1, "x1"    # Z

    .line 65
    iput-boolean p1, p0, Landroidx/databinding/ViewDataBinding;->mRebindHalted:Z

    return p1
.end method

.method static synthetic access$100(Landroidx/databinding/ViewDataBinding;)Ljava/lang/Runnable;
    .locals 1
    .param p0, "x0"    # Landroidx/databinding/ViewDataBinding;

    .line 65
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mRebindRunnable:Ljava/lang/Runnable;

    return-object v0
.end method

.method static synthetic access$202(Landroidx/databinding/ViewDataBinding;Z)Z
    .locals 0
    .param p0, "x0"    # Landroidx/databinding/ViewDataBinding;
    .param p1, "x1"    # Z

    .line 65
    iput-boolean p1, p0, Landroidx/databinding/ViewDataBinding;->mPendingRebind:Z

    return p1
.end method

.method static synthetic access$300()V
    .locals 0

    .line 65
    invoke-static {}, Landroidx/databinding/ViewDataBinding;->processReferenceQueue()V

    return-void
.end method

.method static synthetic access$400(Landroidx/databinding/ViewDataBinding;)Landroid/view/View;
    .locals 1
    .param p0, "x0"    # Landroidx/databinding/ViewDataBinding;

    .line 65
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mRoot:Landroid/view/View;

    return-object v0
.end method

.method static synthetic access$500()Landroid/view/View$OnAttachStateChangeListener;
    .locals 1

    .line 65
    sget-object v0, Landroidx/databinding/ViewDataBinding;->ROOT_REATTACHED_LISTENER:Landroid/view/View$OnAttachStateChangeListener;

    return-object v0
.end method

.method static synthetic access$700()Ljava/lang/ref/ReferenceQueue;
    .locals 1

    .line 65
    sget-object v0, Landroidx/databinding/ViewDataBinding;->sReferenceQueue:Ljava/lang/ref/ReferenceQueue;

    return-object v0
.end method

.method static synthetic access$800(Landroidx/databinding/ViewDataBinding;ILjava/lang/Object;I)V
    .locals 0
    .param p0, "x0"    # Landroidx/databinding/ViewDataBinding;
    .param p1, "x1"    # I
    .param p2, "x2"    # Ljava/lang/Object;
    .param p3, "x3"    # I

    .line 65
    invoke-direct {p0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;->handleFieldChange(ILjava/lang/Object;I)V

    return-void
.end method

.method protected static bind(Ljava/lang/Object;Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;
    .locals 1
    .param p0, "bindingComponent"    # Ljava/lang/Object;
    .param p1, "view"    # Landroid/view/View;
    .param p2, "layoutId"    # I

    .line 695
    nop

    .line 696
    invoke-static {p0}, Landroidx/databinding/ViewDataBinding;->checkAndCastToBindingComponent(Ljava/lang/Object;)Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    .line 695
    invoke-static {v0, p1, p2}, Landroidx/databinding/DataBindingUtil;->bind(Landroidx/databinding/DataBindingComponent;Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    return-object v0
.end method

.method private static checkAndCastToBindingComponent(Ljava/lang/Object;)Landroidx/databinding/DataBindingComponent;
    .locals 2
    .param p0, "bindingComponent"    # Ljava/lang/Object;

    .line 308
    if-nez p0, :cond_0

    .line 309
    const/4 v0, 0x0

    return-object v0

    .line 311
    :cond_0
    instance-of v0, p0, Landroidx/databinding/DataBindingComponent;

    if-eqz v0, :cond_1

    .line 317
    move-object v0, p0

    check-cast v0, Landroidx/databinding/DataBindingComponent;

    return-object v0

    .line 312
    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "The provided bindingComponent parameter must be an instance of DataBindingComponent. See  https://issuetracker.google.com/issues/116541301 for details of why this parameter is not defined as DataBindingComponent"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method private executeBindingsInternal()V
    .locals 4

    .line 455
    iget-boolean v0, p0, Landroidx/databinding/ViewDataBinding;->mIsExecutingPendingBindings:Z

    if-eqz v0, :cond_0

    .line 456
    invoke-virtual {p0}, Landroidx/databinding/ViewDataBinding;->requestRebind()V

    .line 457
    return-void

    .line 459
    :cond_0
    invoke-virtual {p0}, Landroidx/databinding/ViewDataBinding;->hasPendingBindings()Z

    move-result v0

    if-nez v0, :cond_1

    .line 460
    return-void

    .line 462
    :cond_1
    const/4 v0, 0x1

    iput-boolean v0, p0, Landroidx/databinding/ViewDataBinding;->mIsExecutingPendingBindings:Z

    .line 463
    const/4 v1, 0x0

    iput-boolean v1, p0, Landroidx/databinding/ViewDataBinding;->mRebindHalted:Z

    .line 464
    iget-object v2, p0, Landroidx/databinding/ViewDataBinding;->mRebindCallbacks:Landroidx/databinding/CallbackRegistry;

    const/4 v3, 0x0

    if-eqz v2, :cond_2

    .line 465
    invoke-virtual {v2, p0, v0, v3}, Landroidx/databinding/CallbackRegistry;->notifyCallbacks(Ljava/lang/Object;ILjava/lang/Object;)V

    .line 468
    iget-boolean v0, p0, Landroidx/databinding/ViewDataBinding;->mRebindHalted:Z

    if-eqz v0, :cond_2

    .line 469
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mRebindCallbacks:Landroidx/databinding/CallbackRegistry;

    const/4 v2, 0x2

    invoke-virtual {v0, p0, v2, v3}, Landroidx/databinding/CallbackRegistry;->notifyCallbacks(Ljava/lang/Object;ILjava/lang/Object;)V

    .line 472
    :cond_2
    iget-boolean v0, p0, Landroidx/databinding/ViewDataBinding;->mRebindHalted:Z

    if-nez v0, :cond_3

    .line 473
    invoke-virtual {p0}, Landroidx/databinding/ViewDataBinding;->executeBindings()V

    .line 474
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mRebindCallbacks:Landroidx/databinding/CallbackRegistry;

    if-eqz v0, :cond_3

    .line 475
    const/4 v2, 0x3

    invoke-virtual {v0, p0, v2, v3}, Landroidx/databinding/CallbackRegistry;->notifyCallbacks(Ljava/lang/Object;ILjava/lang/Object;)V

    .line 478
    :cond_3
    iput-boolean v1, p0, Landroidx/databinding/ViewDataBinding;->mIsExecutingPendingBindings:Z

    .line 479
    return-void
.end method

.method protected static executeBindingsOn(Landroidx/databinding/ViewDataBinding;)V
    .locals 0
    .param p0, "other"    # Landroidx/databinding/ViewDataBinding;

    .line 487
    invoke-direct {p0}, Landroidx/databinding/ViewDataBinding;->executeBindingsInternal()V

    .line 488
    return-void
.end method

.method private static findIncludeIndex(Ljava/lang/String;ILandroidx/databinding/ViewDataBinding$IncludedLayouts;I)I
    .locals 7
    .param p0, "tag"    # Ljava/lang/String;
    .param p1, "minInclude"    # I
    .param p2, "included"    # Landroidx/databinding/ViewDataBinding$IncludedLayouts;
    .param p3, "includedIndex"    # I

    .line 1276
    const/16 v0, 0x2f

    invoke-virtual {p0, v0}, Ljava/lang/String;->indexOf(I)I

    move-result v0

    .line 1277
    .local v0, "slashIndex":I
    add-int/lit8 v1, v0, 0x1

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v2

    add-int/lit8 v2, v2, -0x2

    invoke-virtual {p0, v1, v2}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    move-result-object v1

    .line 1279
    .local v1, "layoutName":Ljava/lang/CharSequence;
    iget-object v2, p2, Landroidx/databinding/ViewDataBinding$IncludedLayouts;->layouts:[[Ljava/lang/String;

    aget-object v2, v2, p3

    .line 1280
    .local v2, "layouts":[Ljava/lang/String;
    array-length v3, v2

    .line 1281
    .local v3, "length":I
    move v4, p1

    .local v4, "i":I
    :goto_0
    if-ge v4, v3, :cond_1

    .line 1282
    aget-object v5, v2, v4

    .line 1283
    .local v5, "layout":Ljava/lang/String;
    invoke-static {v1, v5}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    move-result v6

    if-eqz v6, :cond_0

    .line 1284
    return v4

    .line 1281
    .end local v5    # "layout":Ljava/lang/String;
    :cond_0
    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    .line 1287
    .end local v4    # "i":I
    :cond_1
    const/4 v4, -0x1

    return v4
.end method

.method private static findLastMatching(Landroid/view/ViewGroup;I)I
    .locals 12
    .param p0, "viewGroup"    # Landroid/view/ViewGroup;
    .param p1, "firstIncludedIndex"    # I

    .line 1291
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v0

    .line 1292
    .local v0, "firstView":Landroid/view/View;
    invoke-virtual {v0}, Landroid/view/View;->getTag()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    .line 1293
    .local v1, "firstViewTag":Ljava/lang/String;
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v2

    add-int/lit8 v2, v2, -0x1

    const/4 v3, 0x0

    invoke-virtual {v1, v3, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v2

    .line 1294
    .local v2, "tagBase":Ljava/lang/String;
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v3

    .line 1296
    .local v3, "tagSequenceIndex":I
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v4

    .line 1297
    .local v4, "count":I
    move v5, p1

    .line 1298
    .local v5, "max":I
    add-int/lit8 v6, p1, 0x1

    .local v6, "i":I
    :goto_0
    if-ge v6, v4, :cond_3

    .line 1299
    invoke-virtual {p0, v6}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v7

    .line 1300
    .local v7, "view":Landroid/view/View;
    invoke-virtual {v7}, Landroid/view/View;->getTag()Ljava/lang/Object;

    move-result-object v8

    .line 1301
    .local v8, "objTag":Ljava/lang/Object;
    instance-of v9, v8, Ljava/lang/String;

    if-eqz v9, :cond_0

    invoke-virtual {v7}, Landroid/view/View;->getTag()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/String;

    goto :goto_1

    :cond_0
    const/4 v9, 0x0

    .line 1302
    .local v9, "tag":Ljava/lang/String;
    :goto_1
    if-eqz v9, :cond_2

    invoke-virtual {v9, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v10

    if-eqz v10, :cond_2

    .line 1303
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    move-result v10

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v11

    if-ne v10, v11, :cond_1

    invoke-virtual {v9}, Ljava/lang/String;->length()I

    move-result v10

    add-int/lit8 v10, v10, -0x1

    invoke-virtual {v9, v10}, Ljava/lang/String;->charAt(I)C

    move-result v10

    const/16 v11, 0x30

    if-ne v10, v11, :cond_1

    .line 1304
    return v5

    .line 1306
    :cond_1
    invoke-static {v9, v3}, Landroidx/databinding/ViewDataBinding;->isNumeric(Ljava/lang/String;I)Z

    move-result v10

    if-eqz v10, :cond_2

    .line 1307
    move v5, v6

    .line 1298
    .end local v7    # "view":Landroid/view/View;
    .end local v8    # "objTag":Ljava/lang/Object;
    .end local v9    # "tag":Ljava/lang/String;
    :cond_2
    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    .line 1311
    .end local v6    # "i":I
    :cond_3
    return v5
.end method

.method static getBinding(Landroid/view/View;)Landroidx/databinding/ViewDataBinding;
    .locals 1
    .param p0, "v"    # Landroid/view/View;

    .line 524
    if-eqz p0, :cond_0

    .line 525
    sget v0, Landroidx/databinding/library/R$id;->dataBinding:I

    invoke-virtual {p0, v0}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/databinding/ViewDataBinding;

    return-object v0

    .line 527
    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public static getBuildSdkInt()I
    .locals 1

    .line 342
    sget v0, Landroidx/databinding/ViewDataBinding;->SDK_INT:I

    return v0
.end method

.method protected static getColorFromResource(Landroid/view/View;I)I
    .locals 2
    .param p0, "view"    # Landroid/view/View;
    .param p1, "resourceId"    # I

    .line 795
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x17

    if-lt v0, v1, :cond_0

    .line 796
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-virtual {v0, p1}, Landroid/content/Context;->getColor(I)I

    move-result v0

    return v0

    .line 798
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0, p1}, Landroid/content/res/Resources;->getColor(I)I

    move-result v0

    return v0
.end method

.method protected static getColorStateListFromResource(Landroid/view/View;I)Landroid/content/res/ColorStateList;
    .locals 2
    .param p0, "view"    # Landroid/view/View;
    .param p1, "resourceId"    # I

    .line 804
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x17

    if-lt v0, v1, :cond_0

    .line 805
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-virtual {v0, p1}, Landroid/content/Context;->getColorStateList(I)Landroid/content/res/ColorStateList;

    move-result-object v0

    return-object v0

    .line 807
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0, p1}, Landroid/content/res/Resources;->getColorStateList(I)Landroid/content/res/ColorStateList;

    move-result-object v0

    return-object v0
.end method

.method protected static getDrawableFromResource(Landroid/view/View;I)Landroid/graphics/drawable/Drawable;
    .locals 2
    .param p0, "view"    # Landroid/view/View;
    .param p1, "resourceId"    # I

    .line 813
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x15

    if-lt v0, v1, :cond_0

    .line 814
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-virtual {v0, p1}, Landroid/content/Context;->getDrawable(I)Landroid/graphics/drawable/Drawable;

    move-result-object v0

    return-object v0

    .line 816
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0, p1}, Landroid/content/res/Resources;->getDrawable(I)Landroid/graphics/drawable/Drawable;

    move-result-object v0

    return-object v0
.end method

.method protected static getFrom(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<K:",
            "Ljava/lang/Object;",
            "T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/Map<",
            "TK;TT;>;TK;)TT;"
        }
    .end annotation

    .line 1083
    .local p0, "map":Ljava/util/Map;, "Ljava/util/Map<TK;TT;>;"
    .local p1, "key":Ljava/lang/Object;, "TK;"
    if-nez p0, :cond_0

    .line 1084
    const/4 v0, 0x0

    return-object v0

    .line 1086
    :cond_0
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method protected static getFromArray([BI)B
    .locals 1
    .param p0, "arr"    # [B
    .param p1, "index"    # I

    .line 854
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 857
    :cond_0
    aget-byte v0, p0, p1

    return v0

    .line 855
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return v0
.end method

.method protected static getFromArray([CI)C
    .locals 1
    .param p0, "arr"    # [C
    .param p1, "index"    # I

    .line 886
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 889
    :cond_0
    aget-char v0, p0, p1

    return v0

    .line 887
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return v0
.end method

.method protected static getFromArray([DI)D
    .locals 2
    .param p0, "arr"    # [D
    .param p1, "index"    # I

    .line 950
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 953
    :cond_0
    aget-wide v0, p0, p1

    return-wide v0

    .line 951
    :cond_1
    :goto_0
    const-wide/16 v0, 0x0

    return-wide v0
.end method

.method protected static getFromArray([FI)F
    .locals 1
    .param p0, "arr"    # [F
    .param p1, "index"    # I

    .line 934
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 937
    :cond_0
    aget v0, p0, p1

    return v0

    .line 935
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return v0
.end method

.method protected static getFromArray([II)I
    .locals 1
    .param p0, "arr"    # [I
    .param p1, "index"    # I

    .line 902
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 905
    :cond_0
    aget v0, p0, p1

    return v0

    .line 903
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return v0
.end method

.method protected static getFromArray([JI)J
    .locals 2
    .param p0, "arr"    # [J
    .param p1, "index"    # I

    .line 918
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 921
    :cond_0
    aget-wide v0, p0, p1

    return-wide v0

    .line 919
    :cond_1
    :goto_0
    const-wide/16 v0, 0x0

    return-wide v0
.end method

.method protected static getFromArray([Ljava/lang/Object;I)Ljava/lang/Object;
    .locals 1
    .param p1, "index"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">([TT;I)TT;"
        }
    .end annotation

    .line 822
    .local p0, "arr":[Ljava/lang/Object;, "[TT;"
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 825
    :cond_0
    aget-object v0, p0, p1

    return-object v0

    .line 823
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return-object v0
.end method

.method protected static getFromArray([SI)S
    .locals 1
    .param p0, "arr"    # [S
    .param p1, "index"    # I

    .line 870
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 873
    :cond_0
    aget-short v0, p0, p1

    return v0

    .line 871
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return v0
.end method

.method protected static getFromArray([ZI)Z
    .locals 1
    .param p0, "arr"    # [Z
    .param p1, "index"    # I

    .line 838
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 841
    :cond_0
    aget-boolean v0, p0, p1

    return v0

    .line 839
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return v0
.end method

.method protected static getFromList(Landroid/util/SparseIntArray;I)I
    .locals 1
    .param p0, "list"    # Landroid/util/SparseIntArray;
    .param p1, "index"    # I

    .line 1049
    if-eqz p0, :cond_1

    if-gez p1, :cond_0

    goto :goto_0

    .line 1052
    :cond_0
    invoke-virtual {p0, p1}, Landroid/util/SparseIntArray;->get(I)I

    move-result v0

    return v0

    .line 1050
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return v0
.end method

.method protected static getFromList(Landroid/util/SparseLongArray;I)J
    .locals 2
    .param p0, "list"    # Landroid/util/SparseLongArray;
    .param p1, "index"    # I

    .line 1066
    if-eqz p0, :cond_1

    if-gez p1, :cond_0

    goto :goto_0

    .line 1069
    :cond_0
    invoke-virtual {p0, p1}, Landroid/util/SparseLongArray;->get(I)J

    move-result-wide v0

    return-wide v0

    .line 1067
    :cond_1
    :goto_0
    const-wide/16 v0, 0x0

    return-wide v0
.end method

.method protected static getFromList(Landroid/util/LongSparseArray;I)Ljava/lang/Object;
    .locals 2
    .param p1, "index"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Landroid/util/LongSparseArray<",
            "TT;>;I)TT;"
        }
    .end annotation

    .line 999
    .local p0, "list":Landroid/util/LongSparseArray;, "Landroid/util/LongSparseArray<TT;>;"
    if-eqz p0, :cond_1

    if-gez p1, :cond_0

    goto :goto_0

    .line 1002
    :cond_0
    int-to-long v0, p1

    invoke-virtual {p0, v0, v1}, Landroid/util/LongSparseArray;->get(J)Ljava/lang/Object;

    move-result-object v0

    return-object v0

    .line 1000
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return-object v0
.end method

.method protected static getFromList(Landroid/util/SparseArray;I)Ljava/lang/Object;
    .locals 1
    .param p1, "index"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Landroid/util/SparseArray<",
            "TT;>;I)TT;"
        }
    .end annotation

    .line 982
    .local p0, "list":Landroid/util/SparseArray;, "Landroid/util/SparseArray<TT;>;"
    if-eqz p0, :cond_1

    if-gez p1, :cond_0

    goto :goto_0

    .line 985
    :cond_0
    invoke-virtual {p0, p1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    move-result-object v0

    return-object v0

    .line 983
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return-object v0
.end method

.method protected static getFromList(Landroidx/collection/LongSparseArray;I)Ljava/lang/Object;
    .locals 2
    .param p1, "index"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Landroidx/collection/LongSparseArray<",
            "TT;>;I)TT;"
        }
    .end annotation

    .line 1016
    .local p0, "list":Landroidx/collection/LongSparseArray;, "Landroidx/collection/LongSparseArray<TT;>;"
    if-eqz p0, :cond_1

    if-gez p1, :cond_0

    goto :goto_0

    .line 1019
    :cond_0
    int-to-long v0, p1

    invoke-virtual {p0, v0, v1}, Landroidx/collection/LongSparseArray;->get(J)Ljava/lang/Object;

    move-result-object v0

    return-object v0

    .line 1017
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return-object v0
.end method

.method protected static getFromList(Ljava/util/List;I)Ljava/lang/Object;
    .locals 1
    .param p1, "index"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/List<",
            "TT;>;I)TT;"
        }
    .end annotation

    .line 966
    .local p0, "list":Ljava/util/List;, "Ljava/util/List<TT;>;"
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result v0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 969
    :cond_0
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    return-object v0

    .line 967
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return-object v0
.end method

.method protected static getFromList(Landroid/util/SparseBooleanArray;I)Z
    .locals 1
    .param p0, "list"    # Landroid/util/SparseBooleanArray;
    .param p1, "index"    # I

    .line 1033
    if-eqz p0, :cond_1

    if-gez p1, :cond_0

    goto :goto_0

    .line 1036
    :cond_0
    invoke-virtual {p0, p1}, Landroid/util/SparseBooleanArray;->get(I)Z

    move-result v0

    return v0

    .line 1034
    :cond_1
    :goto_0
    const/4 v0, 0x0

    return v0
.end method

.method private handleFieldChange(ILjava/lang/Object;I)V
    .locals 1
    .param p1, "mLocalFieldId"    # I
    .param p2, "object"    # Ljava/lang/Object;
    .param p3, "fieldId"    # I

    .line 543
    iget-boolean v0, p0, Landroidx/databinding/ViewDataBinding;->mInLiveDataRegisterObserver:Z

    if-eqz v0, :cond_0

    .line 547
    return-void

    .line 549
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;->onFieldChange(ILjava/lang/Object;I)Z

    move-result v0

    .line 550
    .local v0, "result":Z
    if-eqz v0, :cond_1

    .line 551
    invoke-virtual {p0}, Landroidx/databinding/ViewDataBinding;->requestRebind()V

    .line 553
    :cond_1
    return-void
.end method

.method protected static inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;
    .locals 1
    .param p0, "inflater"    # Landroid/view/LayoutInflater;
    .param p1, "layoutId"    # I
    .param p2, "parent"    # Landroid/view/ViewGroup;
    .param p3, "attachToParent"    # Z
    .param p4, "bindingComponent"    # Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Landroidx/databinding/ViewDataBinding;",
            ">(",
            "Landroid/view/LayoutInflater;",
            "I",
            "Landroid/view/ViewGroup;",
            "Z",
            "Ljava/lang/Object;",
            ")TT;"
        }
    .end annotation

    .line 1368
    nop

    .line 1373
    invoke-static {p4}, Landroidx/databinding/ViewDataBinding;->checkAndCastToBindingComponent(Ljava/lang/Object;)Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    .line 1368
    invoke-static {p0, p1, p2, p3, v0}, Landroidx/databinding/DataBindingUtil;->inflate(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLandroidx/databinding/DataBindingComponent;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    return-object v0
.end method

.method private static isNumeric(Ljava/lang/String;I)Z
    .locals 4
    .param p0, "tag"    # Ljava/lang/String;
    .param p1, "startIndex"    # I

    .line 1315
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    .line 1316
    .local v0, "length":I
    const/4 v1, 0x0

    if-ne v0, p1, :cond_0

    .line 1317
    return v1

    .line 1319
    :cond_0
    move v2, p1

    .local v2, "i":I
    :goto_0
    if-ge v2, v0, :cond_2

    .line 1320
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    move-result v3

    invoke-static {v3}, Ljava/lang/Character;->isDigit(C)Z

    move-result v3

    if-nez v3, :cond_1

    .line 1321
    return v1

    .line 1319
    :cond_1
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 1324
    .end local v2    # "i":I
    :cond_2
    const/4 v1, 0x1

    return v1
.end method

.method private static mapBindings(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;Landroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;Z)V
    .locals 23
    .param p0, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p1, "view"    # Landroid/view/View;
    .param p2, "bindings"    # [Ljava/lang/Object;
    .param p3, "includes"    # Landroidx/databinding/ViewDataBinding$IncludedLayouts;
    .param p4, "viewsWithIds"    # Landroid/util/SparseIntArray;
    .param p5, "isRoot"    # Z

    .line 1190
    move-object/from16 v6, p0

    move-object/from16 v7, p1

    move-object/from16 v8, p3

    move-object/from16 v9, p4

    invoke-static/range {p1 .. p1}, Landroidx/databinding/ViewDataBinding;->getBinding(Landroid/view/View;)Landroidx/databinding/ViewDataBinding;

    move-result-object v10

    .line 1191
    .local v10, "existingBinding":Landroidx/databinding/ViewDataBinding;
    if-eqz v10, :cond_0

    .line 1192
    return-void

    .line 1194
    :cond_0
    invoke-virtual/range {p1 .. p1}, Landroid/view/View;->getTag()Ljava/lang/Object;

    move-result-object v11

    .line 1195
    .local v11, "objTag":Ljava/lang/Object;
    instance-of v0, v11, Ljava/lang/String;

    if-eqz v0, :cond_1

    move-object v0, v11

    check-cast v0, Ljava/lang/String;

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    move-object v12, v0

    .line 1196
    .local v12, "tag":Ljava/lang/String;
    const/4 v0, 0x0

    .line 1197
    .local v0, "isBound":Z
    const-string v13, "layout"

    const/4 v1, -0x1

    if-eqz p5, :cond_5

    if-eqz v12, :cond_5

    invoke-virtual {v12, v13}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v2

    if-eqz v2, :cond_5

    .line 1198
    const/16 v2, 0x5f

    invoke-virtual {v12, v2}, Ljava/lang/String;->lastIndexOf(I)I

    move-result v2

    .line 1199
    .local v2, "underscoreIndex":I
    if-lez v2, :cond_4

    add-int/lit8 v3, v2, 0x1

    invoke-static {v12, v3}, Landroidx/databinding/ViewDataBinding;->isNumeric(Ljava/lang/String;I)Z

    move-result v3

    if-eqz v3, :cond_4

    .line 1200
    add-int/lit8 v3, v2, 0x1

    invoke-static {v12, v3}, Landroidx/databinding/ViewDataBinding;->parseTagInt(Ljava/lang/String;I)I

    move-result v3

    .line 1201
    .local v3, "index":I
    aget-object v4, p2, v3

    if-nez v4, :cond_2

    .line 1202
    aput-object v7, p2, v3

    .line 1204
    :cond_2
    if-nez v8, :cond_3

    const/4 v4, -0x1

    goto :goto_1

    :cond_3
    move v4, v3

    .line 1205
    .local v4, "indexInIncludes":I
    :goto_1
    const/4 v0, 0x1

    .line 1206
    .end local v3    # "index":I
    goto :goto_2

    .line 1207
    .end local v4    # "indexInIncludes":I
    :cond_4
    const/4 v4, -0x1

    .line 1209
    .end local v2    # "underscoreIndex":I
    .restart local v4    # "indexInIncludes":I
    :goto_2
    move v14, v0

    move v15, v4

    goto :goto_4

    .end local v4    # "indexInIncludes":I
    :cond_5
    if-eqz v12, :cond_8

    const-string v2, "binding_"

    invoke-virtual {v12, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v2

    if-eqz v2, :cond_8

    .line 1210
    sget v2, Landroidx/databinding/ViewDataBinding;->BINDING_NUMBER_START:I

    invoke-static {v12, v2}, Landroidx/databinding/ViewDataBinding;->parseTagInt(Ljava/lang/String;I)I

    move-result v2

    .line 1211
    .local v2, "tagIndex":I
    aget-object v3, p2, v2

    if-nez v3, :cond_6

    .line 1212
    aput-object v7, p2, v2

    .line 1214
    :cond_6
    const/4 v0, 0x1

    .line 1215
    if-nez v8, :cond_7

    const/4 v3, -0x1

    goto :goto_3

    :cond_7
    move v3, v2

    :goto_3
    move v4, v3

    .line 1216
    .end local v2    # "tagIndex":I
    .restart local v4    # "indexInIncludes":I
    move v14, v0

    move v15, v4

    goto :goto_4

    .line 1218
    .end local v4    # "indexInIncludes":I
    :cond_8
    const/4 v4, -0x1

    move v14, v0

    move v15, v4

    .line 1220
    .end local v0    # "isBound":Z
    .local v14, "isBound":Z
    .local v15, "indexInIncludes":I
    :goto_4
    if-nez v14, :cond_9

    .line 1221
    invoke-virtual/range {p1 .. p1}, Landroid/view/View;->getId()I

    move-result v0

    .line 1222
    .local v0, "id":I
    if-lez v0, :cond_9

    .line 1224
    if-eqz v9, :cond_9

    invoke-virtual {v9, v0, v1}, Landroid/util/SparseIntArray;->get(II)I

    move-result v1

    move v2, v1

    .local v2, "index":I
    if-ltz v1, :cond_9

    aget-object v1, p2, v2

    if-nez v1, :cond_9

    .line 1226
    aput-object v7, p2, v2

    .line 1231
    .end local v0    # "id":I
    .end local v2    # "index":I
    :cond_9
    instance-of v0, v7, Landroid/view/ViewGroup;

    if-eqz v0, :cond_13

    .line 1232
    move-object v5, v7

    check-cast v5, Landroid/view/ViewGroup;

    .line 1233
    .local v5, "viewGroup":Landroid/view/ViewGroup;
    invoke-virtual {v5}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v4

    .line 1234
    .local v4, "count":I
    const/4 v0, 0x0

    .line 1235
    .local v0, "minInclude":I
    const/4 v1, 0x0

    .local v1, "i":I
    :goto_5
    if-ge v1, v4, :cond_12

    .line 1236
    invoke-virtual {v5, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v3

    .line 1237
    .local v3, "child":Landroid/view/View;
    const/4 v2, 0x0

    .line 1238
    .local v2, "isInclude":Z
    if-ltz v15, :cond_10

    move/from16 v16, v2

    .end local v2    # "isInclude":Z
    .local v16, "isInclude":Z
    invoke-virtual {v3}, Landroid/view/View;->getTag()Ljava/lang/Object;

    move-result-object v2

    instance-of v2, v2, Ljava/lang/String;

    if-eqz v2, :cond_f

    .line 1239
    invoke-virtual {v3}, Landroid/view/View;->getTag()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    .line 1240
    .local v2, "childTag":Ljava/lang/String;
    move/from16 v17, v4

    .end local v4    # "count":I
    .local v17, "count":I
    const-string v4, "_0"

    invoke-virtual {v2, v4}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    move-result v4

    if-eqz v4, :cond_e

    .line 1241
    invoke-virtual {v2, v13}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v4

    if-eqz v4, :cond_d

    const/16 v4, 0x2f

    invoke-virtual {v2, v4}, Ljava/lang/String;->indexOf(I)I

    move-result v4

    if-lez v4, :cond_d

    .line 1243
    invoke-static {v2, v0, v8, v15}, Landroidx/databinding/ViewDataBinding;->findIncludeIndex(Ljava/lang/String;ILandroidx/databinding/ViewDataBinding$IncludedLayouts;I)I

    move-result v4

    .line 1245
    .local v4, "includeIndex":I
    if-ltz v4, :cond_c

    .line 1246
    const/16 v16, 0x1

    .line 1247
    add-int/lit8 v0, v4, 0x1

    .line 1248
    move/from16 v18, v0

    .end local v0    # "minInclude":I
    .local v18, "minInclude":I
    iget-object v0, v8, Landroidx/databinding/ViewDataBinding$IncludedLayouts;->indexes:[[I

    aget-object v0, v0, v15

    aget v0, v0, v4

    .line 1249
    .local v0, "index":I
    move-object/from16 v19, v2

    .end local v2    # "childTag":Ljava/lang/String;
    .local v19, "childTag":Ljava/lang/String;
    iget-object v2, v8, Landroidx/databinding/ViewDataBinding$IncludedLayouts;->layoutIds:[[I

    aget-object v2, v2, v15

    aget v2, v2, v4

    .line 1250
    .local v2, "layoutId":I
    move/from16 v20, v4

    .end local v4    # "includeIndex":I
    .local v20, "includeIndex":I
    invoke-static {v5, v1}, Landroidx/databinding/ViewDataBinding;->findLastMatching(Landroid/view/ViewGroup;I)I

    move-result v4

    .line 1251
    .local v4, "lastMatchingIndex":I
    if-ne v4, v1, :cond_a

    .line 1252
    invoke-static {v6, v3, v2}, Landroidx/databinding/DataBindingUtil;->bind(Landroidx/databinding/DataBindingComponent;Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;

    move-result-object v21

    aput-object v21, p2, v0

    move v7, v1

    goto :goto_8

    .line 1255
    :cond_a
    sub-int v21, v4, v1

    move/from16 v22, v4

    .end local v4    # "lastMatchingIndex":I
    .local v22, "lastMatchingIndex":I
    add-int/lit8 v4, v21, 0x1

    .line 1256
    .local v4, "includeCount":I
    new-array v7, v4, [Landroid/view/View;

    .line 1257
    .local v7, "included":[Landroid/view/View;
    const/16 v21, 0x0

    move/from16 v8, v21

    .local v8, "j":I
    :goto_6
    if-ge v8, v4, :cond_b

    .line 1258
    add-int v9, v1, v8

    invoke-virtual {v5, v9}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v9

    aput-object v9, v7, v8

    .line 1257
    add-int/lit8 v8, v8, 0x1

    move-object/from16 v9, p4

    goto :goto_6

    .line 1260
    .end local v8    # "j":I
    :cond_b
    invoke-static {v6, v7, v2}, Landroidx/databinding/DataBindingUtil;->bind(Landroidx/databinding/DataBindingComponent;[Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;

    move-result-object v8

    aput-object v8, p2, v0

    .line 1262
    add-int/lit8 v8, v4, -0x1

    add-int/2addr v1, v8

    move v7, v1

    goto :goto_8

    .line 1245
    .end local v7    # "included":[Landroid/view/View;
    .end local v18    # "minInclude":I
    .end local v19    # "childTag":Ljava/lang/String;
    .end local v20    # "includeIndex":I
    .end local v22    # "lastMatchingIndex":I
    .local v0, "minInclude":I
    .local v2, "childTag":Ljava/lang/String;
    .local v4, "includeIndex":I
    :cond_c
    move-object/from16 v19, v2

    move/from16 v20, v4

    .end local v2    # "childTag":Ljava/lang/String;
    .end local v4    # "includeIndex":I
    .restart local v19    # "childTag":Ljava/lang/String;
    .restart local v20    # "includeIndex":I
    goto :goto_7

    .line 1241
    .end local v19    # "childTag":Ljava/lang/String;
    .end local v20    # "includeIndex":I
    .restart local v2    # "childTag":Ljava/lang/String;
    :cond_d
    move-object/from16 v19, v2

    .end local v2    # "childTag":Ljava/lang/String;
    .restart local v19    # "childTag":Ljava/lang/String;
    goto :goto_7

    .line 1240
    .end local v19    # "childTag":Ljava/lang/String;
    .restart local v2    # "childTag":Ljava/lang/String;
    :cond_e
    move-object/from16 v19, v2

    .end local v2    # "childTag":Ljava/lang/String;
    .restart local v19    # "childTag":Ljava/lang/String;
    goto :goto_7

    .line 1238
    .end local v17    # "count":I
    .end local v19    # "childTag":Ljava/lang/String;
    .local v4, "count":I
    :cond_f
    move/from16 v17, v4

    .end local v4    # "count":I
    .restart local v17    # "count":I
    goto :goto_7

    .end local v16    # "isInclude":Z
    .end local v17    # "count":I
    .local v2, "isInclude":Z
    .restart local v4    # "count":I
    :cond_10
    move/from16 v16, v2

    move/from16 v17, v4

    .line 1267
    .end local v2    # "isInclude":Z
    .end local v4    # "count":I
    .restart local v16    # "isInclude":Z
    .restart local v17    # "count":I
    :goto_7
    move/from16 v18, v0

    move v7, v1

    .end local v0    # "minInclude":I
    .end local v1    # "i":I
    .local v7, "i":I
    .restart local v18    # "minInclude":I
    :goto_8
    if-nez v16, :cond_11

    .line 1268
    const/4 v8, 0x0

    move-object/from16 v0, p0

    move-object v1, v3

    move-object/from16 v2, p2

    move-object v9, v3

    .end local v3    # "child":Landroid/view/View;
    .local v9, "child":Landroid/view/View;
    move-object/from16 v3, p3

    move-object/from16 v4, p4

    move-object/from16 v19, v5

    .end local v5    # "viewGroup":Landroid/view/ViewGroup;
    .local v19, "viewGroup":Landroid/view/ViewGroup;
    move v5, v8

    invoke-static/range {v0 .. v5}, Landroidx/databinding/ViewDataBinding;->mapBindings(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;Landroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;Z)V

    goto :goto_9

    .line 1267
    .end local v9    # "child":Landroid/view/View;
    .end local v19    # "viewGroup":Landroid/view/ViewGroup;
    .restart local v3    # "child":Landroid/view/View;
    .restart local v5    # "viewGroup":Landroid/view/ViewGroup;
    :cond_11
    move-object v9, v3

    move-object/from16 v19, v5

    .line 1235
    .end local v3    # "child":Landroid/view/View;
    .end local v5    # "viewGroup":Landroid/view/ViewGroup;
    .end local v16    # "isInclude":Z
    .restart local v19    # "viewGroup":Landroid/view/ViewGroup;
    :goto_9
    add-int/lit8 v1, v7, 0x1

    move-object/from16 v7, p1

    move-object/from16 v8, p3

    move-object/from16 v9, p4

    move/from16 v4, v17

    move/from16 v0, v18

    move-object/from16 v5, v19

    .end local v7    # "i":I
    .restart local v1    # "i":I
    goto/16 :goto_5

    .end local v17    # "count":I
    .end local v18    # "minInclude":I
    .end local v19    # "viewGroup":Landroid/view/ViewGroup;
    .restart local v0    # "minInclude":I
    .restart local v4    # "count":I
    .restart local v5    # "viewGroup":Landroid/view/ViewGroup;
    :cond_12
    move/from16 v17, v4

    move-object/from16 v19, v5

    .line 1272
    .end local v0    # "minInclude":I
    .end local v1    # "i":I
    .end local v4    # "count":I
    .end local v5    # "viewGroup":Landroid/view/ViewGroup;
    :cond_13
    return-void
.end method

.method protected static mapBindings(Landroidx/databinding/DataBindingComponent;Landroid/view/View;ILandroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;)[Ljava/lang/Object;
    .locals 7
    .param p0, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p1, "root"    # Landroid/view/View;
    .param p2, "numBindings"    # I
    .param p3, "includes"    # Landroidx/databinding/ViewDataBinding$IncludedLayouts;
    .param p4, "viewsWithIds"    # Landroid/util/SparseIntArray;

    .line 718
    new-array v6, p2, [Ljava/lang/Object;

    .line 719
    .local v6, "bindings":[Ljava/lang/Object;
    const/4 v5, 0x1

    move-object v0, p0

    move-object v1, p1

    move-object v2, v6

    move-object v3, p3

    move-object v4, p4

    invoke-static/range {v0 .. v5}, Landroidx/databinding/ViewDataBinding;->mapBindings(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;Landroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;Z)V

    .line 720
    return-object v6
.end method

.method protected static mapBindings(Landroidx/databinding/DataBindingComponent;[Landroid/view/View;ILandroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;)[Ljava/lang/Object;
    .locals 8
    .param p0, "bindingComponent"    # Landroidx/databinding/DataBindingComponent;
    .param p1, "roots"    # [Landroid/view/View;
    .param p2, "numBindings"    # I
    .param p3, "includes"    # Landroidx/databinding/ViewDataBinding$IncludedLayouts;
    .param p4, "viewsWithIds"    # Landroid/util/SparseIntArray;

    .line 1179
    new-array v6, p2, [Ljava/lang/Object;

    .line 1180
    .local v6, "bindings":[Ljava/lang/Object;
    const/4 v0, 0x0

    move v7, v0

    .local v7, "i":I
    :goto_0
    array-length v0, p1

    if-ge v7, v0, :cond_0

    .line 1181
    aget-object v1, p1, v7

    const/4 v5, 0x1

    move-object v0, p0

    move-object v2, v6

    move-object v3, p3

    move-object v4, p4

    invoke-static/range {v0 .. v5}, Landroidx/databinding/ViewDataBinding;->mapBindings(Landroidx/databinding/DataBindingComponent;Landroid/view/View;[Ljava/lang/Object;Landroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;Z)V

    .line 1180
    add-int/lit8 v7, v7, 0x1

    goto :goto_0

    .line 1183
    .end local v7    # "i":I
    :cond_0
    return-object v6
.end method

.method protected static parse(Ljava/lang/String;B)B
    .locals 1
    .param p0, "str"    # Ljava/lang/String;
    .param p1, "fallback"    # B

    .line 734
    :try_start_0
    invoke-static {p0}, Ljava/lang/Byte;->parseByte(Ljava/lang/String;)B

    move-result v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    return v0

    .line 735
    :catch_0
    move-exception v0

    .line 736
    .local v0, "e":Ljava/lang/NumberFormatException;
    return p1
.end method

.method protected static parse(Ljava/lang/String;C)C
    .locals 1
    .param p0, "str"    # Ljava/lang/String;
    .param p1, "fallback"    # C

    .line 787
    if-eqz p0, :cond_1

    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 790
    :cond_0
    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C

    move-result v0

    return v0

    .line 788
    :cond_1
    :goto_0
    return p1
.end method

.method protected static parse(Ljava/lang/String;D)D
    .locals 2
    .param p0, "str"    # Ljava/lang/String;
    .param p1, "fallback"    # D

    .line 779
    :try_start_0
    invoke-static {p0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    move-result-wide v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    return-wide v0

    .line 780
    :catch_0
    move-exception v0

    .line 781
    .local v0, "e":Ljava/lang/NumberFormatException;
    return-wide p1
.end method

.method protected static parse(Ljava/lang/String;F)F
    .locals 1
    .param p0, "str"    # Ljava/lang/String;
    .param p1, "fallback"    # F

    .line 770
    :try_start_0
    invoke-static {p0}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    return v0

    .line 771
    :catch_0
    move-exception v0

    .line 772
    .local v0, "e":Ljava/lang/NumberFormatException;
    return p1
.end method

.method protected static parse(Ljava/lang/String;I)I
    .locals 1
    .param p0, "str"    # Ljava/lang/String;
    .param p1, "fallback"    # I

    .line 752
    :try_start_0
    invoke-static {p0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    return v0

    .line 753
    :catch_0
    move-exception v0

    .line 754
    .local v0, "e":Ljava/lang/NumberFormatException;
    return p1
.end method

.method protected static parse(Ljava/lang/String;J)J
    .locals 2
    .param p0, "str"    # Ljava/lang/String;
    .param p1, "fallback"    # J

    .line 761
    :try_start_0
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    return-wide v0

    .line 762
    :catch_0
    move-exception v0

    .line 763
    .local v0, "e":Ljava/lang/NumberFormatException;
    return-wide p1
.end method

.method protected static parse(Ljava/lang/String;S)S
    .locals 1
    .param p0, "str"    # Ljava/lang/String;
    .param p1, "fallback"    # S

    .line 743
    :try_start_0
    invoke-static {p0}, Ljava/lang/Short;->parseShort(Ljava/lang/String;)S

    move-result v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    return v0

    .line 744
    :catch_0
    move-exception v0

    .line 745
    .local v0, "e":Ljava/lang/NumberFormatException;
    return p1
.end method

.method protected static parse(Ljava/lang/String;Z)Z
    .locals 1
    .param p0, "str"    # Ljava/lang/String;
    .param p1, "fallback"    # Z

    .line 725
    if-nez p0, :cond_0

    .line 726
    return p1

    .line 728
    :cond_0
    invoke-static {p0}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    move-result v0

    return v0
.end method

.method private static parseTagInt(Ljava/lang/String;I)I
    .locals 5
    .param p0, "str"    # Ljava/lang/String;
    .param p1, "startIndex"    # I

    .line 1334
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    .line 1335
    .local v0, "end":I
    const/4 v1, 0x0

    .line 1336
    .local v1, "val":I
    move v2, p1

    .local v2, "i":I
    :goto_0
    if-ge v2, v0, :cond_0

    .line 1337
    mul-int/lit8 v1, v1, 0xa

    .line 1338
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    move-result v3

    .line 1339
    .local v3, "c":C
    add-int/lit8 v4, v3, -0x30

    add-int/2addr v1, v4

    .line 1336
    .end local v3    # "c":C
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 1341
    .end local v2    # "i":I
    :cond_0
    return v1
.end method

.method private static processReferenceQueue()V
    .locals 2

    .line 1349
    :cond_0
    :goto_0
    sget-object v0, Landroidx/databinding/ViewDataBinding;->sReferenceQueue:Ljava/lang/ref/ReferenceQueue;

    invoke-virtual {v0}, Ljava/lang/ref/ReferenceQueue;->poll()Ljava/lang/ref/Reference;

    move-result-object v0

    move-object v1, v0

    .local v1, "ref":Ljava/lang/ref/Reference;, "Ljava/lang/ref/Reference<+Landroidx/databinding/ViewDataBinding;>;"
    if-eqz v0, :cond_1

    .line 1350
    instance-of v0, v1, Landroidx/databinding/ViewDataBinding$WeakListener;

    if-eqz v0, :cond_0

    .line 1351
    move-object v0, v1

    check-cast v0, Landroidx/databinding/ViewDataBinding$WeakListener;

    .line 1352
    .local v0, "listener":Landroidx/databinding/ViewDataBinding$WeakListener;
    invoke-virtual {v0}, Landroidx/databinding/ViewDataBinding$WeakListener;->unregister()Z

    .line 1353
    .end local v0    # "listener":Landroidx/databinding/ViewDataBinding$WeakListener;
    goto :goto_0

    .line 1355
    :cond_1
    return-void
.end method

.method protected static safeUnbox(Ljava/lang/Byte;)B
    .locals 1
    .param p0, "boxed"    # Ljava/lang/Byte;

    .line 1128
    if-nez p0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Byte;->byteValue()B

    move-result v0

    :goto_0
    return v0
.end method

.method protected static safeUnbox(Ljava/lang/Character;)C
    .locals 1
    .param p0, "boxed"    # Ljava/lang/Character;

    .line 1133
    if-nez p0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Character;->charValue()C

    move-result v0

    :goto_0
    return v0
.end method

.method protected static safeUnbox(Ljava/lang/Double;)D
    .locals 2
    .param p0, "boxed"    # Ljava/lang/Double;

    .line 1138
    if-nez p0, :cond_0

    const-wide/16 v0, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Double;->doubleValue()D

    move-result-wide v0

    :goto_0
    return-wide v0
.end method

.method protected static safeUnbox(Ljava/lang/Float;)F
    .locals 1
    .param p0, "boxed"    # Ljava/lang/Float;

    .line 1143
    if-nez p0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    move-result v0

    :goto_0
    return v0
.end method

.method protected static safeUnbox(Ljava/lang/Integer;)I
    .locals 1
    .param p0, "boxed"    # Ljava/lang/Integer;

    .line 1113
    if-nez p0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    move-result v0

    :goto_0
    return v0
.end method

.method protected static safeUnbox(Ljava/lang/Long;)J
    .locals 2
    .param p0, "boxed"    # Ljava/lang/Long;

    .line 1118
    if-nez p0, :cond_0

    const-wide/16 v0, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    move-result-wide v0

    :goto_0
    return-wide v0
.end method

.method protected static safeUnbox(Ljava/lang/Short;)S
    .locals 1
    .param p0, "boxed"    # Ljava/lang/Short;

    .line 1123
    if-nez p0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Short;->shortValue()S

    move-result v0

    :goto_0
    return v0
.end method

.method protected static safeUnbox(Ljava/lang/Boolean;)Z
    .locals 1
    .param p0, "boxed"    # Ljava/lang/Boolean;

    .line 1148
    if-nez p0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    :goto_0
    return v0
.end method

.method protected static setBindingInverseListener(Landroidx/databinding/ViewDataBinding;Landroidx/databinding/InverseBindingListener;Landroidx/databinding/ViewDataBinding$PropertyChangedInverseListener;)V
    .locals 1
    .param p0, "binder"    # Landroidx/databinding/ViewDataBinding;
    .param p1, "oldListener"    # Landroidx/databinding/InverseBindingListener;
    .param p2, "listener"    # Landroidx/databinding/ViewDataBinding$PropertyChangedInverseListener;

    .line 1100
    if-eq p1, p2, :cond_1

    .line 1101
    if-eqz p1, :cond_0

    .line 1102
    move-object v0, p1

    check-cast v0, Landroidx/databinding/ViewDataBinding$PropertyChangedInverseListener;

    invoke-virtual {p0, v0}, Landroidx/databinding/ViewDataBinding;->removeOnPropertyChangedCallback(Landroidx/databinding/Observable$OnPropertyChangedCallback;)V

    .line 1105
    :cond_0
    if-eqz p2, :cond_1

    .line 1106
    invoke-virtual {p0, p2}, Landroidx/databinding/ViewDataBinding;->addOnPropertyChangedCallback(Landroidx/databinding/Observable$OnPropertyChangedCallback;)V

    .line 1109
    :cond_1
    return-void
.end method

.method protected static setTo(Landroid/util/LongSparseArray;ILjava/lang/Object;)V
    .locals 2
    .param p1, "index"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Landroid/util/LongSparseArray<",
            "TT;>;ITT;)V"
        }
    .end annotation

    .line 1008
    .local p0, "list":Landroid/util/LongSparseArray;, "Landroid/util/LongSparseArray<TT;>;"
    .local p2, "value":Ljava/lang/Object;, "TT;"
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    invoke-virtual {p0}, Landroid/util/LongSparseArray;->size()I

    move-result v0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 1011
    :cond_0
    int-to-long v0, p1

    invoke-virtual {p0, v0, v1, p2}, Landroid/util/LongSparseArray;->put(JLjava/lang/Object;)V

    .line 1012
    return-void

    .line 1009
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo(Landroid/util/SparseArray;ILjava/lang/Object;)V
    .locals 1
    .param p1, "index"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Landroid/util/SparseArray<",
            "TT;>;ITT;)V"
        }
    .end annotation

    .line 990
    .local p0, "list":Landroid/util/SparseArray;, "Landroid/util/SparseArray<TT;>;"
    .local p2, "value":Ljava/lang/Object;, "TT;"
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    invoke-virtual {p0}, Landroid/util/SparseArray;->size()I

    move-result v0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 993
    :cond_0
    invoke-virtual {p0, p1, p2}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 994
    return-void

    .line 991
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo(Landroid/util/SparseBooleanArray;IZ)V
    .locals 1
    .param p0, "list"    # Landroid/util/SparseBooleanArray;
    .param p1, "index"    # I
    .param p2, "value"    # Z

    .line 1041
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    invoke-virtual {p0}, Landroid/util/SparseBooleanArray;->size()I

    move-result v0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 1044
    :cond_0
    invoke-virtual {p0, p1, p2}, Landroid/util/SparseBooleanArray;->put(IZ)V

    .line 1045
    return-void

    .line 1042
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo(Landroid/util/SparseIntArray;II)V
    .locals 1
    .param p0, "list"    # Landroid/util/SparseIntArray;
    .param p1, "index"    # I
    .param p2, "value"    # I

    .line 1057
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    invoke-virtual {p0}, Landroid/util/SparseIntArray;->size()I

    move-result v0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 1060
    :cond_0
    invoke-virtual {p0, p1, p2}, Landroid/util/SparseIntArray;->put(II)V

    .line 1061
    return-void

    .line 1058
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo(Landroid/util/SparseLongArray;IJ)V
    .locals 1
    .param p0, "list"    # Landroid/util/SparseLongArray;
    .param p1, "index"    # I
    .param p2, "value"    # J

    .line 1075
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    invoke-virtual {p0}, Landroid/util/SparseLongArray;->size()I

    move-result v0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 1078
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Landroid/util/SparseLongArray;->put(IJ)V

    .line 1079
    return-void

    .line 1076
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo(Landroidx/collection/LongSparseArray;ILjava/lang/Object;)V
    .locals 2
    .param p1, "index"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Landroidx/collection/LongSparseArray<",
            "TT;>;ITT;)V"
        }
    .end annotation

    .line 1025
    .local p0, "list":Landroidx/collection/LongSparseArray;, "Landroidx/collection/LongSparseArray<TT;>;"
    .local p2, "value":Ljava/lang/Object;, "TT;"
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    invoke-virtual {p0}, Landroidx/collection/LongSparseArray;->size()I

    move-result v0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 1028
    :cond_0
    int-to-long v0, p1

    invoke-virtual {p0, v0, v1, p2}, Landroidx/collection/LongSparseArray;->put(JLjava/lang/Object;)V

    .line 1029
    return-void

    .line 1026
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo(Ljava/util/List;ILjava/lang/Object;)V
    .locals 1
    .param p1, "index"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/List<",
            "TT;>;ITT;)V"
        }
    .end annotation

    .line 974
    .local p0, "list":Ljava/util/List;, "Ljava/util/List<TT;>;"
    .local p2, "value":Ljava/lang/Object;, "TT;"
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result v0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 977
    :cond_0
    invoke-interface {p0, p1, p2}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 978
    return-void

    .line 975
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo(Ljava/util/Map;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<K:",
            "Ljava/lang/Object;",
            "T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/Map<",
            "TK;TT;>;TK;TT;)V"
        }
    .end annotation

    .line 1091
    .local p0, "map":Ljava/util/Map;, "Ljava/util/Map<TK;TT;>;"
    .local p1, "key":Ljava/lang/Object;, "TK;"
    .local p2, "value":Ljava/lang/Object;, "TT;"
    if-nez p0, :cond_0

    .line 1092
    return-void

    .line 1094
    :cond_0
    invoke-interface {p0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1095
    return-void
.end method

.method protected static setTo([BIB)V
    .locals 1
    .param p0, "arr"    # [B
    .param p1, "index"    # I
    .param p2, "value"    # B

    .line 862
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 865
    :cond_0
    aput-byte p2, p0, p1

    .line 866
    return-void

    .line 863
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo([CIC)V
    .locals 1
    .param p0, "arr"    # [C
    .param p1, "index"    # I
    .param p2, "value"    # C

    .line 894
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 897
    :cond_0
    aput-char p2, p0, p1

    .line 898
    return-void

    .line 895
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo([DID)V
    .locals 1
    .param p0, "arr"    # [D
    .param p1, "index"    # I
    .param p2, "value"    # D

    .line 958
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 961
    :cond_0
    aput-wide p2, p0, p1

    .line 962
    return-void

    .line 959
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo([FIF)V
    .locals 1
    .param p0, "arr"    # [F
    .param p1, "index"    # I
    .param p2, "value"    # F

    .line 942
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 945
    :cond_0
    aput p2, p0, p1

    .line 946
    return-void

    .line 943
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo([III)V
    .locals 1
    .param p0, "arr"    # [I
    .param p1, "index"    # I
    .param p2, "value"    # I

    .line 910
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 913
    :cond_0
    aput p2, p0, p1

    .line 914
    return-void

    .line 911
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo([JIJ)V
    .locals 1
    .param p0, "arr"    # [J
    .param p1, "index"    # I
    .param p2, "value"    # J

    .line 926
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 929
    :cond_0
    aput-wide p2, p0, p1

    .line 930
    return-void

    .line 927
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo([Ljava/lang/Object;ILjava/lang/Object;)V
    .locals 1
    .param p1, "index"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">([TT;ITT;)V"
        }
    .end annotation

    .line 830
    .local p0, "arr":[Ljava/lang/Object;, "[TT;"
    .local p2, "value":Ljava/lang/Object;, "TT;"
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 833
    :cond_0
    aput-object p2, p0, p1

    .line 834
    return-void

    .line 831
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo([SIS)V
    .locals 1
    .param p0, "arr"    # [S
    .param p1, "index"    # I
    .param p2, "value"    # S

    .line 878
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 881
    :cond_0
    aput-short p2, p0, p1

    .line 882
    return-void

    .line 879
    :cond_1
    :goto_0
    return-void
.end method

.method protected static setTo([ZIZ)V
    .locals 1
    .param p0, "arr"    # [Z
    .param p1, "index"    # I
    .param p2, "value"    # Z

    .line 846
    if-eqz p0, :cond_1

    if-ltz p1, :cond_1

    array-length v0, p0

    if-lt p1, v0, :cond_0

    goto :goto_0

    .line 849
    :cond_0
    aput-boolean p2, p0, p1

    .line 850
    return-void

    .line 847
    :cond_1
    :goto_0
    return-void
.end method

.method private updateRegistration(ILjava/lang/Object;Landroidx/databinding/ViewDataBinding$CreateWeakListener;)Z
    .locals 3
    .param p1, "localFieldId"    # I
    .param p2, "observable"    # Ljava/lang/Object;
    .param p3, "listenerCreator"    # Landroidx/databinding/ViewDataBinding$CreateWeakListener;

    .line 607
    if-nez p2, :cond_0

    .line 608
    invoke-virtual {p0, p1}, Landroidx/databinding/ViewDataBinding;->unregisterFrom(I)Z

    move-result v0

    return v0

    .line 610
    :cond_0
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mLocalFieldObservers:[Landroidx/databinding/ViewDataBinding$WeakListener;

    aget-object v0, v0, p1

    .line 611
    .local v0, "listener":Landroidx/databinding/ViewDataBinding$WeakListener;
    const/4 v1, 0x1

    if-nez v0, :cond_1

    .line 612
    invoke-virtual {p0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;->registerTo(ILjava/lang/Object;Landroidx/databinding/ViewDataBinding$CreateWeakListener;)V

    .line 613
    return v1

    .line 615
    :cond_1
    invoke-virtual {v0}, Landroidx/databinding/ViewDataBinding$WeakListener;->getTarget()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, p2, :cond_2

    .line 616
    const/4 v1, 0x0

    return v1

    .line 618
    :cond_2
    invoke-virtual {p0, p1}, Landroidx/databinding/ViewDataBinding;->unregisterFrom(I)Z

    .line 619
    invoke-virtual {p0, p1, p2, p3}, Landroidx/databinding/ViewDataBinding;->registerTo(ILjava/lang/Object;Landroidx/databinding/ViewDataBinding$CreateWeakListener;)V

    .line 620
    return v1
.end method


# virtual methods
.method public addOnRebindCallback(Landroidx/databinding/OnRebindCallback;)V
    .locals 2
    .param p1, "listener"    # Landroidx/databinding/OnRebindCallback;

    .line 422
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mRebindCallbacks:Landroidx/databinding/CallbackRegistry;

    if-nez v0, :cond_0

    .line 423
    new-instance v0, Landroidx/databinding/CallbackRegistry;

    sget-object v1, Landroidx/databinding/ViewDataBinding;->REBIND_NOTIFIER:Landroidx/databinding/CallbackRegistry$NotifierCallback;

    invoke-direct {v0, v1}, Landroidx/databinding/CallbackRegistry;-><init>(Landroidx/databinding/CallbackRegistry$NotifierCallback;)V

    iput-object v0, p0, Landroidx/databinding/ViewDataBinding;->mRebindCallbacks:Landroidx/databinding/CallbackRegistry;

    .line 425
    :cond_0
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mRebindCallbacks:Landroidx/databinding/CallbackRegistry;

    invoke-virtual {v0, p1}, Landroidx/databinding/CallbackRegistry;->add(Ljava/lang/Object;)V

    .line 426
    return-void
.end method

.method protected ensureBindingComponentIsNotNull(Ljava/lang/Class;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Class<",
            "*>;)V"
        }
    .end annotation

    .line 660
    .local p1, "oneExample":Ljava/lang/Class;, "Ljava/lang/Class<*>;"
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mBindingComponent:Landroidx/databinding/DataBindingComponent;

    if-eqz v0, :cond_0

    .line 670
    return-void

    .line 661
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Required DataBindingComponent is null in class "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 662
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ". A BindingAdapter in "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 663
    invoke-virtual {p1}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " is not static and requires an object to use, retrieved from the DataBindingComponent. If you don\'t use an inflation method taking a DataBindingComponent, use DataBindingUtil.setDefaultComponent or make all BindingAdapter methods static."

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 668
    .local v0, "errorMessage":Ljava/lang/String;
    new-instance v1, Ljava/lang/IllegalStateException;

    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1
.end method

.method protected abstract executeBindings()V
.end method

.method public executePendingBindings()V
    .locals 1

    .line 444
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mContainingBinding:Landroidx/databinding/ViewDataBinding;

    if-nez v0, :cond_0

    .line 445
    invoke-direct {p0}, Landroidx/databinding/ViewDataBinding;->executeBindingsInternal()V

    goto :goto_0

    .line 447
    :cond_0
    invoke-virtual {v0}, Landroidx/databinding/ViewDataBinding;->executePendingBindings()V

    .line 449
    :goto_0
    return-void
.end method

.method forceExecuteBindings()V
    .locals 0

    .line 492
    invoke-virtual {p0}, Landroidx/databinding/ViewDataBinding;->executeBindings()V

    .line 493
    return-void
.end method

.method public getLifecycleOwner()Landroidx/lifecycle/LifecycleOwner;
    .locals 1

    .line 412
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mLifecycleOwner:Landroidx/lifecycle/LifecycleOwner;

    return-object v0
.end method

.method protected getObservedField(I)Ljava/lang/Object;
    .locals 2
    .param p1, "localFieldId"    # I

    .line 598
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mLocalFieldObservers:[Landroidx/databinding/ViewDataBinding$WeakListener;

    aget-object v0, v0, p1

    .line 599
    .local v0, "listener":Landroidx/databinding/ViewDataBinding$WeakListener;
    if-nez v0, :cond_0

    .line 600
    const/4 v1, 0x0

    return-object v1

    .line 602
    :cond_0
    invoke-virtual {v0}, Landroidx/databinding/ViewDataBinding$WeakListener;->getTarget()Ljava/lang/Object;

    move-result-object v1

    return-object v1
.end method

.method public getRoot()Landroid/view/View;
    .locals 1

    .line 539
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mRoot:Landroid/view/View;

    return-object v0
.end method

.method public abstract hasPendingBindings()Z
.end method

.method public abstract invalidateAll()V
.end method

.method protected abstract onFieldChange(ILjava/lang/Object;I)Z
.end method

.method protected registerTo(ILjava/lang/Object;Landroidx/databinding/ViewDataBinding$CreateWeakListener;)V
    .locals 2
    .param p1, "localFieldId"    # I
    .param p2, "observable"    # Ljava/lang/Object;
    .param p3, "listenerCreator"    # Landroidx/databinding/ViewDataBinding$CreateWeakListener;

    .line 677
    if-nez p2, :cond_0

    .line 678
    return-void

    .line 680
    :cond_0
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mLocalFieldObservers:[Landroidx/databinding/ViewDataBinding$WeakListener;

    aget-object v0, v0, p1

    .line 681
    .local v0, "listener":Landroidx/databinding/ViewDataBinding$WeakListener;
    if-nez v0, :cond_1

    .line 682
    invoke-interface {p3, p0, p1}, Landroidx/databinding/ViewDataBinding$CreateWeakListener;->create(Landroidx/databinding/ViewDataBinding;I)Landroidx/databinding/ViewDataBinding$WeakListener;

    move-result-object v0

    .line 683
    iget-object v1, p0, Landroidx/databinding/ViewDataBinding;->mLocalFieldObservers:[Landroidx/databinding/ViewDataBinding$WeakListener;

    aput-object v0, v1, p1

    .line 684
    iget-object v1, p0, Landroidx/databinding/ViewDataBinding;->mLifecycleOwner:Landroidx/lifecycle/LifecycleOwner;

    if-eqz v1, :cond_1

    .line 685
    invoke-virtual {v0, v1}, Landroidx/databinding/ViewDataBinding$WeakListener;->setLifecycleOwner(Landroidx/lifecycle/LifecycleOwner;)V

    .line 688
    :cond_1
    invoke-virtual {v0, p2}, Landroidx/databinding/ViewDataBinding$WeakListener;->setTarget(Ljava/lang/Object;)V

    .line 689
    return-void
.end method

.method public removeOnRebindCallback(Landroidx/databinding/OnRebindCallback;)V
    .locals 1
    .param p1, "listener"    # Landroidx/databinding/OnRebindCallback;

    .line 434
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mRebindCallbacks:Landroidx/databinding/CallbackRegistry;

    if-eqz v0, :cond_0

    .line 435
    invoke-virtual {v0, p1}, Landroidx/databinding/CallbackRegistry;->remove(Ljava/lang/Object;)V

    .line 437
    :cond_0
    return-void
.end method

.method protected requestRebind()V
    .locals 3

    .line 570
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mContainingBinding:Landroidx/databinding/ViewDataBinding;

    if-eqz v0, :cond_0

    .line 571
    invoke-virtual {v0}, Landroidx/databinding/ViewDataBinding;->requestRebind()V

    goto :goto_0

    .line 573
    :cond_0
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mLifecycleOwner:Landroidx/lifecycle/LifecycleOwner;

    .line 574
    .local v0, "owner":Landroidx/lifecycle/LifecycleOwner;
    if-eqz v0, :cond_1

    .line 575
    invoke-interface {v0}, Landroidx/lifecycle/LifecycleOwner;->getLifecycle()Landroidx/lifecycle/Lifecycle;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/lifecycle/Lifecycle;->getCurrentState()Landroidx/lifecycle/Lifecycle$State;

    move-result-object v1

    .line 576
    .local v1, "state":Landroidx/lifecycle/Lifecycle$State;
    sget-object v2, Landroidx/lifecycle/Lifecycle$State;->STARTED:Landroidx/lifecycle/Lifecycle$State;

    invoke-virtual {v1, v2}, Landroidx/lifecycle/Lifecycle$State;->isAtLeast(Landroidx/lifecycle/Lifecycle$State;)Z

    move-result v2

    if-nez v2, :cond_1

    .line 577
    return-void

    .line 580
    .end local v1    # "state":Landroidx/lifecycle/Lifecycle$State;
    :cond_1
    monitor-enter p0

    .line 581
    :try_start_0
    iget-boolean v1, p0, Landroidx/databinding/ViewDataBinding;->mPendingRebind:Z

    if-eqz v1, :cond_2

    .line 582
    monitor-exit p0

    return-void

    .line 584
    :cond_2
    const/4 v1, 0x1

    iput-boolean v1, p0, Landroidx/databinding/ViewDataBinding;->mPendingRebind:Z

    .line 585
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 586
    sget-boolean v1, Landroidx/databinding/ViewDataBinding;->USE_CHOREOGRAPHER:Z

    if-eqz v1, :cond_3

    .line 587
    iget-object v1, p0, Landroidx/databinding/ViewDataBinding;->mChoreographer:Landroid/view/Choreographer;

    iget-object v2, p0, Landroidx/databinding/ViewDataBinding;->mFrameCallback:Landroid/view/Choreographer$FrameCallback;

    invoke-virtual {v1, v2}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    goto :goto_0

    .line 589
    :cond_3
    iget-object v1, p0, Landroidx/databinding/ViewDataBinding;->mUIThreadHandler:Landroid/os/Handler;

    iget-object v2, p0, Landroidx/databinding/ViewDataBinding;->mRebindRunnable:Ljava/lang/Runnable;

    invoke-virtual {v1, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 592
    .end local v0    # "owner":Landroidx/lifecycle/LifecycleOwner;
    :goto_0
    return-void

    .line 585
    .restart local v0    # "owner":Landroidx/lifecycle/LifecycleOwner;
    :catchall_0
    move-exception v1

    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v1
.end method

.method protected setContainedBinding(Landroidx/databinding/ViewDataBinding;)V
    .locals 0
    .param p1, "included"    # Landroidx/databinding/ViewDataBinding;

    .line 1157
    if-eqz p1, :cond_0

    .line 1158
    iput-object p0, p1, Landroidx/databinding/ViewDataBinding;->mContainingBinding:Landroidx/databinding/ViewDataBinding;

    .line 1160
    :cond_0
    return-void
.end method

.method public setLifecycleOwner(Landroidx/lifecycle/LifecycleOwner;)V
    .locals 4
    .param p1, "lifecycleOwner"    # Landroidx/lifecycle/LifecycleOwner;

    .line 384
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mLifecycleOwner:Landroidx/lifecycle/LifecycleOwner;

    if-ne v0, p1, :cond_0

    .line 385
    return-void

    .line 387
    :cond_0
    if-eqz v0, :cond_1

    .line 388
    invoke-interface {v0}, Landroidx/lifecycle/LifecycleOwner;->getLifecycle()Landroidx/lifecycle/Lifecycle;

    move-result-object v0

    iget-object v1, p0, Landroidx/databinding/ViewDataBinding;->mOnStartListener:Landroidx/databinding/ViewDataBinding$OnStartListener;

    invoke-virtual {v0, v1}, Landroidx/lifecycle/Lifecycle;->removeObserver(Landroidx/lifecycle/LifecycleObserver;)V

    .line 390
    :cond_1
    iput-object p1, p0, Landroidx/databinding/ViewDataBinding;->mLifecycleOwner:Landroidx/lifecycle/LifecycleOwner;

    .line 391
    if-eqz p1, :cond_3

    .line 392
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mOnStartListener:Landroidx/databinding/ViewDataBinding$OnStartListener;

    if-nez v0, :cond_2

    .line 393
    new-instance v0, Landroidx/databinding/ViewDataBinding$OnStartListener;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Landroidx/databinding/ViewDataBinding$OnStartListener;-><init>(Landroidx/databinding/ViewDataBinding;Landroidx/databinding/ViewDataBinding$1;)V

    iput-object v0, p0, Landroidx/databinding/ViewDataBinding;->mOnStartListener:Landroidx/databinding/ViewDataBinding$OnStartListener;

    .line 395
    :cond_2
    invoke-interface {p1}, Landroidx/lifecycle/LifecycleOwner;->getLifecycle()Landroidx/lifecycle/Lifecycle;

    move-result-object v0

    iget-object v1, p0, Landroidx/databinding/ViewDataBinding;->mOnStartListener:Landroidx/databinding/ViewDataBinding$OnStartListener;

    invoke-virtual {v0, v1}, Landroidx/lifecycle/Lifecycle;->addObserver(Landroidx/lifecycle/LifecycleObserver;)V

    .line 397
    :cond_3
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mLocalFieldObservers:[Landroidx/databinding/ViewDataBinding$WeakListener;

    array-length v1, v0

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_5

    aget-object v3, v0, v2

    .line 398
    .local v3, "weakListener":Landroidx/databinding/ViewDataBinding$WeakListener;, "Landroidx/databinding/ViewDataBinding$WeakListener<*>;"
    if-eqz v3, :cond_4

    .line 399
    invoke-virtual {v3, p1}, Landroidx/databinding/ViewDataBinding$WeakListener;->setLifecycleOwner(Landroidx/lifecycle/LifecycleOwner;)V

    .line 397
    .end local v3    # "weakListener":Landroidx/databinding/ViewDataBinding$WeakListener;, "Landroidx/databinding/ViewDataBinding$WeakListener<*>;"
    :cond_4
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 402
    :cond_5
    return-void
.end method

.method protected setRootTag(Landroid/view/View;)V
    .locals 1
    .param p1, "view"    # Landroid/view/View;

    .line 324
    sget v0, Landroidx/databinding/library/R$id;->dataBinding:I

    invoke-virtual {p1, v0, p0}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 325
    return-void
.end method

.method protected setRootTag([Landroid/view/View;)V
    .locals 4
    .param p1, "views"    # [Landroid/view/View;

    .line 331
    array-length v0, p1

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    aget-object v2, p1, v1

    .line 332
    .local v2, "view":Landroid/view/View;
    sget v3, Landroidx/databinding/library/R$id;->dataBinding:I

    invoke-virtual {v2, v3, p0}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 331
    .end local v2    # "view":Landroid/view/View;
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 334
    :cond_0
    return-void
.end method

.method public abstract setVariable(ILjava/lang/Object;)Z
.end method

.method public unbind()V
    .locals 4

    .line 516
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mLocalFieldObservers:[Landroidx/databinding/ViewDataBinding$WeakListener;

    array-length v1, v0

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_1

    aget-object v3, v0, v2

    .line 517
    .local v3, "weakListener":Landroidx/databinding/ViewDataBinding$WeakListener;
    if-eqz v3, :cond_0

    .line 518
    invoke-virtual {v3}, Landroidx/databinding/ViewDataBinding$WeakListener;->unregister()Z

    .line 516
    .end local v3    # "weakListener":Landroidx/databinding/ViewDataBinding$WeakListener;
    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 521
    :cond_1
    return-void
.end method

.method protected unregisterFrom(I)Z
    .locals 2
    .param p1, "localFieldId"    # I

    .line 559
    iget-object v0, p0, Landroidx/databinding/ViewDataBinding;->mLocalFieldObservers:[Landroidx/databinding/ViewDataBinding$WeakListener;

    aget-object v0, v0, p1

    .line 560
    .local v0, "listener":Landroidx/databinding/ViewDataBinding$WeakListener;
    if-eqz v0, :cond_0

    .line 561
    invoke-virtual {v0}, Landroidx/databinding/ViewDataBinding$WeakListener;->unregister()Z

    move-result v1

    return v1

    .line 563
    :cond_0
    const/4 v1, 0x0

    return v1
.end method

.method protected updateLiveDataRegistration(ILandroidx/lifecycle/LiveData;)Z
    .locals 2
    .param p1, "localFieldId"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I",
            "Landroidx/lifecycle/LiveData<",
            "*>;)Z"
        }
    .end annotation

    .line 648
    .local p2, "observable":Landroidx/lifecycle/LiveData;, "Landroidx/lifecycle/LiveData<*>;"
    const/4 v0, 0x1

    iput-boolean v0, p0, Landroidx/databinding/ViewDataBinding;->mInLiveDataRegisterObserver:Z

    .line 650
    const/4 v0, 0x0

    :try_start_0
    sget-object v1, Landroidx/databinding/ViewDataBinding;->CREATE_LIVE_DATA_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

    invoke-direct {p0, p1, p2, v1}, Landroidx/databinding/ViewDataBinding;->updateRegistration(ILjava/lang/Object;Landroidx/databinding/ViewDataBinding$CreateWeakListener;)Z

    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 652
    iput-boolean v0, p0, Landroidx/databinding/ViewDataBinding;->mInLiveDataRegisterObserver:Z

    .line 650
    return v1

    .line 652
    :catchall_0
    move-exception v1

    iput-boolean v0, p0, Landroidx/databinding/ViewDataBinding;->mInLiveDataRegisterObserver:Z

    .line 653
    throw v1
.end method

.method protected updateRegistration(ILandroidx/databinding/Observable;)Z
    .locals 1
    .param p1, "localFieldId"    # I
    .param p2, "observable"    # Landroidx/databinding/Observable;

    .line 627
    sget-object v0, Landroidx/databinding/ViewDataBinding;->CREATE_PROPERTY_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

    invoke-direct {p0, p1, p2, v0}, Landroidx/databinding/ViewDataBinding;->updateRegistration(ILjava/lang/Object;Landroidx/databinding/ViewDataBinding$CreateWeakListener;)Z

    move-result v0

    return v0
.end method

.method protected updateRegistration(ILandroidx/databinding/ObservableList;)Z
    .locals 1
    .param p1, "localFieldId"    # I
    .param p2, "observable"    # Landroidx/databinding/ObservableList;

    .line 634
    sget-object v0, Landroidx/databinding/ViewDataBinding;->CREATE_LIST_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

    invoke-direct {p0, p1, p2, v0}, Landroidx/databinding/ViewDataBinding;->updateRegistration(ILjava/lang/Object;Landroidx/databinding/ViewDataBinding$CreateWeakListener;)Z

    move-result v0

    return v0
.end method

.method protected updateRegistration(ILandroidx/databinding/ObservableMap;)Z
    .locals 1
    .param p1, "localFieldId"    # I
    .param p2, "observable"    # Landroidx/databinding/ObservableMap;

    .line 641
    sget-object v0, Landroidx/databinding/ViewDataBinding;->CREATE_MAP_LISTENER:Landroidx/databinding/ViewDataBinding$CreateWeakListener;

    invoke-direct {p0, p1, p2, v0}, Landroidx/databinding/ViewDataBinding;->updateRegistration(ILjava/lang/Object;Landroidx/databinding/ViewDataBinding$CreateWeakListener;)Z

    move-result v0

    return v0
.end method
