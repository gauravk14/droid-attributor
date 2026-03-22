.class public Lcom/insecureshop/DataBinderMapperImpl;
.super Landroidx/databinding/DataBinderMapper;
.source "DataBinderMapperImpl.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/insecureshop/DataBinderMapperImpl$InnerLayoutIdLookup;,
        Lcom/insecureshop/DataBinderMapperImpl$InnerBrLookup;
    }
.end annotation


# static fields
.field private static final INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

.field private static final LAYOUT_ACTIVITYIMPLICITINTENTFORNONEXPORTED:I = 0x1

.field private static final LAYOUT_ACTIVITYLOGIN:I = 0x2

.field private static final LAYOUT_ACTIVITYMAIN:I = 0x3

.field private static final LAYOUT_ACTIVITYPRIVATE:I = 0x4

.field private static final LAYOUT_ACTIVITYWEBVIEW:I = 0x5

.field private static final LAYOUT_APPLOADINGDIALOG:I = 0x6

.field private static final LAYOUT_BASEMAIN:I = 0x7

.field private static final LAYOUT_CARTITEM:I = 0x8

.field private static final LAYOUT_FRAGMENTHOME:I = 0x9

.field private static final LAYOUT_PRODUCTITEM:I = 0xa

.field private static final LAYOUT_TOOLBAR:I = 0xb

.field private static final LAYOUT_UPLOADSUCCESSDIALOG:I = 0xc


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 56
    new-instance v0, Landroid/util/SparseIntArray;

    const/16 v1, 0xc

    invoke-direct {v0, v1}, Landroid/util/SparseIntArray;-><init>(I)V

    sput-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    .line 59
    const v2, 0x7f0c001f

    const/4 v3, 0x1

    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->put(II)V

    .line 60
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    const v2, 0x7f0c0020

    const/4 v3, 0x2

    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->put(II)V

    .line 61
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    const v2, 0x7f0c0021

    const/4 v3, 0x3

    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->put(II)V

    .line 62
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    const v2, 0x7f0c0022

    const/4 v3, 0x4

    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->put(II)V

    .line 63
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    const v2, 0x7f0c0024

    const/4 v3, 0x5

    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->put(II)V

    .line 64
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    const v2, 0x7f0c0025

    const/4 v3, 0x6

    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->put(II)V

    .line 65
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    const v2, 0x7f0c0026

    const/4 v3, 0x7

    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->put(II)V

    .line 66
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    const v2, 0x7f0c0027

    const/16 v3, 0x8

    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->put(II)V

    .line 67
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    const v2, 0x7f0c0038

    const/16 v3, 0x9

    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->put(II)V

    .line 68
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    const v2, 0x7f0c0064

    const/16 v3, 0xa

    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->put(II)V

    .line 69
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    const v2, 0x7f0c0075

    const/16 v3, 0xb

    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->put(II)V

    .line 70
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    const v2, 0x7f0c0076

    invoke-virtual {v0, v2, v1}, Landroid/util/SparseIntArray;->put(II)V

    .line 71
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 31
    invoke-direct {p0}, Landroidx/databinding/DataBinderMapper;-><init>()V

    return-void
.end method


# virtual methods
.method public collectDependencies()Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Landroidx/databinding/DataBinderMapper;",
            ">;"
        }
    .end annotation

    .line 193
    new-instance v0, Ljava/util/ArrayList;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 194
    .local v0, "result":Ljava/util/ArrayList;, "Ljava/util/ArrayList<Landroidx/databinding/DataBinderMapper;>;"
    new-instance v1, Landroidx/databinding/library/baseAdapters/DataBinderMapperImpl;

    invoke-direct {v1}, Landroidx/databinding/library/baseAdapters/DataBinderMapperImpl;-><init>()V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 195
    return-object v0
.end method

.method public convertBrIdToString(I)Ljava/lang/String;
    .locals 1
    .param p1, "localId"    # I

    .line 187
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl$InnerBrLookup;->sKeys:Landroid/util/SparseArray;

    invoke-virtual {v0, p1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    .line 188
    .local v0, "tmpVal":Ljava/lang/String;
    return-object v0
.end method

.method public getDataBinder(Landroidx/databinding/DataBindingComponent;Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;
    .locals 5
    .param p1, "component"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "view"    # Landroid/view/View;
    .param p3, "layoutId"    # I

    .line 75
    sget-object v0, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    invoke-virtual {v0, p3}, Landroid/util/SparseIntArray;->get(I)I

    move-result v0

    .line 76
    .local v0, "localizedLayoutId":I
    if-lez v0, :cond_d

    .line 77
    invoke-virtual {p2}, Landroid/view/View;->getTag()Ljava/lang/Object;

    move-result-object v1

    .line 78
    .local v1, "tag":Ljava/lang/Object;
    if-eqz v1, :cond_c

    .line 81
    packed-switch v0, :pswitch_data_0

    goto/16 :goto_0

    .line 149
    :pswitch_0
    const-string v2, "layout/upload_success_dialog_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    .line 150
    new-instance v2, Lcom/insecureshop/databinding/UploadSuccessDialogBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/UploadSuccessDialogBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 152
    :cond_0
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for upload_success_dialog is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 143
    :pswitch_1
    const-string v2, "layout/toolbar_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    .line 144
    new-instance v2, Lcom/insecureshop/databinding/ToolbarBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/ToolbarBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 146
    :cond_1
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for toolbar is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 137
    :pswitch_2
    const-string v2, "layout/product_item_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    .line 138
    new-instance v2, Lcom/insecureshop/databinding/ProductItemBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/ProductItemBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 140
    :cond_2
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for product_item is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 131
    :pswitch_3
    const-string v2, "layout/fragment_home_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_3

    .line 132
    new-instance v2, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/FragmentHomeBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 134
    :cond_3
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for fragment_home is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 125
    :pswitch_4
    const-string v2, "layout/cart_item_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_4

    .line 126
    new-instance v2, Lcom/insecureshop/databinding/CartItemBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/CartItemBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 128
    :cond_4
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for cart_item is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 119
    :pswitch_5
    const-string v2, "layout/base_main_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_5

    .line 120
    new-instance v2, Lcom/insecureshop/databinding/BaseMainBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/BaseMainBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 122
    :cond_5
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for base_main is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 113
    :pswitch_6
    const-string v2, "layout/app_loading_dialog_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_6

    .line 114
    new-instance v2, Lcom/insecureshop/databinding/AppLoadingDialogBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/AppLoadingDialogBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 116
    :cond_6
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for app_loading_dialog is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 107
    :pswitch_7
    const-string v2, "layout/activity_webview_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_7

    .line 108
    new-instance v2, Lcom/insecureshop/databinding/ActivityWebviewBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/ActivityWebviewBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 110
    :cond_7
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for activity_webview is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 101
    :pswitch_8
    const-string v2, "layout/activity_private_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_8

    .line 102
    new-instance v2, Lcom/insecureshop/databinding/ActivityPrivateBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/ActivityPrivateBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 104
    :cond_8
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for activity_private is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 95
    :pswitch_9
    const-string v2, "layout/activity_main_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_9

    .line 96
    new-instance v2, Lcom/insecureshop/databinding/ActivityMainBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/ActivityMainBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 98
    :cond_9
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for activity_main is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 89
    :pswitch_a
    const-string v2, "layout/activity_login_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_a

    .line 90
    new-instance v2, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/ActivityLoginBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 92
    :cond_a
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for activity_login is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 83
    :pswitch_b
    const-string v2, "layout/activity_implicit_intent_for_non_exported_0"

    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_b

    .line 84
    new-instance v2, Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBindingImpl;

    invoke-direct {v2, p1, p2}, Lcom/insecureshop/databinding/ActivityImplicitIntentForNonExportedBindingImpl;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;)V

    return-object v2

    .line 86
    :cond_b
    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "The tag for activity_implicit_intent_for_non_exported is invalid. Received: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 79
    :cond_c
    new-instance v2, Ljava/lang/RuntimeException;

    const-string v3, "view must have a tag"

    invoke-direct {v2, v3}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v2

    .line 156
    .end local v1    # "tag":Ljava/lang/Object;
    :cond_d
    :goto_0
    const/4 v1, 0x0

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public getDataBinder(Landroidx/databinding/DataBindingComponent;[Landroid/view/View;I)Landroidx/databinding/ViewDataBinding;
    .locals 4
    .param p1, "component"    # Landroidx/databinding/DataBindingComponent;
    .param p2, "views"    # [Landroid/view/View;
    .param p3, "layoutId"    # I

    .line 161
    const/4 v0, 0x0

    if-eqz p2, :cond_3

    array-length v1, p2

    if-nez v1, :cond_0

    goto :goto_1

    .line 164
    :cond_0
    sget-object v1, Lcom/insecureshop/DataBinderMapperImpl;->INTERNAL_LAYOUT_ID_LOOKUP:Landroid/util/SparseIntArray;

    invoke-virtual {v1, p3}, Landroid/util/SparseIntArray;->get(I)I

    move-result v1

    .line 165
    .local v1, "localizedLayoutId":I
    if-lez v1, :cond_2

    .line 166
    const/4 v2, 0x0

    aget-object v2, p2, v2

    invoke-virtual {v2}, Landroid/view/View;->getTag()Ljava/lang/Object;

    move-result-object v2

    .line 167
    .local v2, "tag":Ljava/lang/Object;
    if-eqz v2, :cond_1

    .line 170
    goto :goto_0

    .line 168
    :cond_1
    new-instance v0, Ljava/lang/RuntimeException;

    const-string v3, "view must have a tag"

    invoke-direct {v0, v3}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 173
    .end local v2    # "tag":Ljava/lang/Object;
    :cond_2
    :goto_0
    return-object v0

    .line 162
    .end local v1    # "localizedLayoutId":I
    :cond_3
    :goto_1
    return-object v0
.end method

.method public getLayoutId(Ljava/lang/String;)I
    .locals 2
    .param p1, "tag"    # Ljava/lang/String;

    .line 178
    const/4 v0, 0x0

    if-nez p1, :cond_0

    .line 179
    return v0

    .line 181
    :cond_0
    sget-object v1, Lcom/insecureshop/DataBinderMapperImpl$InnerLayoutIdLookup;->sKeys:Ljava/util/HashMap;

    invoke-virtual {v1, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    .line 182
    .local v1, "tmpVal":Ljava/lang/Integer;
    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v0

    :goto_0
    return v0
.end method
