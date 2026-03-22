.class final Landroidx/databinding/ViewDataBinding$6;
.super Ljava/lang/Object;
.source "ViewDataBinding.java"

# interfaces
.implements Landroid/view/View$OnAttachStateChangeListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/databinding/ViewDataBinding;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x8
    name = null
.end annotation


# direct methods
.method constructor <init>()V
    .locals 0

    .line 159
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onViewAttachedToWindow(Landroid/view/View;)V
    .locals 2
    .param p1, "v"    # Landroid/view/View;

    .line 164
    invoke-static {p1}, Landroidx/databinding/ViewDataBinding;->getBinding(Landroid/view/View;)Landroidx/databinding/ViewDataBinding;

    move-result-object v0

    .line 165
    .local v0, "binding":Landroidx/databinding/ViewDataBinding;
    invoke-static {v0}, Landroidx/databinding/ViewDataBinding;->access$100(Landroidx/databinding/ViewDataBinding;)Ljava/lang/Runnable;

    move-result-object v1

    invoke-interface {v1}, Ljava/lang/Runnable;->run()V

    .line 166
    invoke-virtual {p1, p0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 167
    return-void
.end method

.method public onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 0
    .param p1, "v"    # Landroid/view/View;

    .line 171
    return-void
.end method
