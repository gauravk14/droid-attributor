.class public final Lcom/insecureshop/ChooserActivity;
.super Landroidx/appcompat/app/AppCompatActivity;
.source "ChooserActivity.kt"


# annotations
.annotation system Ldalvik/annotation/SourceDebugExtension;
    value = "SMAP\nChooserActivity.kt\nKotlin\n*S Kotlin\n*F\n+ 1 ChooserActivity.kt\ncom/insecureshop/ChooserActivity\n*L\n1#1,77:1\n*E\n"
.end annotation

.annotation runtime Lkotlin/Metadata;
    bv = {
        0x1,
        0x0,
        0x3
    }
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0005\u00a2\u0006\u0002\u0010\u0002J\u0010\u0010\u0003\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0005\u001a\u00020\u0006J\u001c\u0010\u0007\u001a\u0004\u0018\u00010\u00062\u0006\u0010\u0008\u001a\u00020\u00062\u0008\u0010\t\u001a\u0004\u0018\u00010\u0004H\u0002J\u0012\u0010\n\u001a\u00020\u000b2\u0008\u0010\u000c\u001a\u0004\u0018\u00010\rH\u0014\u00a8\u0006\u000e"
    }
    d2 = {
        "Lcom/insecureshop/ChooserActivity;",
        "Landroidx/appcompat/app/AppCompatActivity;",
        "()V",
        "getFilename",
        "",
        "uri",
        "Landroid/net/Uri;",
        "makeTempCopy",
        "fileUri",
        "original_filename",
        "onCreate",
        "",
        "savedInstanceState",
        "Landroid/os/Bundle;",
        "app_debug"
    }
    k = 0x1
    mv = {
        0x1,
        0x1,
        0x10
    }
.end annotation


# instance fields
.field private _$_findViewCache:Ljava/util/HashMap;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 17
    invoke-direct {p0}, Landroidx/appcompat/app/AppCompatActivity;-><init>()V

    return-void
.end method

.method private final makeTempCopy(Landroid/net/Uri;Ljava/lang/String;)Landroid/net/Uri;
    .locals 8
    .param p1, "fileUri"    # Landroid/net/Uri;
    .param p2, "original_filename"    # Ljava/lang/String;

    .line 30
    nop

    .line 31
    const/4 v0, 0x0

    :try_start_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-static {}, Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;

    move-result-object v2

    const-string v3, "Environment.getExternalStorageDirectory()"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget-object v2, Ljava/io/File;->separator:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "insecureshop"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    .line 32
    .local v1, "path":Ljava/lang/String;
    nop

    .line 33
    new-instance v2, Ljava/io/File;

    .end local v1    # "path":Ljava/lang/String;
    invoke-direct {v2, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 32
    nop

    .line 34
    .local v2, "directory":Ljava/io/File;
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v3

    .end local v2    # "directory":Ljava/io/File;
    if-nez v3, :cond_0

    .line 35
    invoke-virtual {v2}, Ljava/io/File;->mkdirs()Z

    .line 37
    :cond_0
    new-instance v2, Ljava/io/File;

    invoke-direct {v2, v1, p2}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    move-object v1, v2

    .line 38
    .local v1, "fileTemp":Ljava/io/File;
    invoke-virtual {v1}, Ljava/io/File;->createNewFile()Z

    .line 39
    .end local v1    # "fileTemp":Ljava/io/File;
    invoke-static {v1}, Landroid/net/Uri;->fromFile(Ljava/io/File;)Landroid/net/Uri;

    move-result-object v1

    .line 41
    .local v1, "out":Landroid/net/Uri;
    invoke-virtual {p0}, Lcom/insecureshop/ChooserActivity;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v2

    .end local v1    # "out":Landroid/net/Uri;
    invoke-virtual {v2, p1}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;

    move-result-object v2

    .line 42
    .local v2, "inputStream":Ljava/io/InputStream;
    invoke-virtual {p0}, Lcom/insecureshop/ChooserActivity;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v3

    .end local v2    # "inputStream":Ljava/io/InputStream;
    invoke-virtual {v3, v1}, Landroid/content/ContentResolver;->openOutputStream(Landroid/net/Uri;)Ljava/io/OutputStream;

    move-result-object v1

    .line 43
    .local v1, "outputStream":Ljava/io/OutputStream;
    const/16 v3, 0x2000

    new-array v3, v3, [B

    .line 44
    .end local v1    # "outputStream":Ljava/io/OutputStream;
    :goto_0
    nop

    .line 45
    if-eqz v2, :cond_1

    invoke-virtual {v2, v3}, Ljava/io/InputStream;->read([B)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    goto :goto_1

    :cond_1
    move-object v4, v0

    .line 46
    .local v4, "len":Ljava/lang/Integer;
    :goto_1
    if-nez v4, :cond_2

    :goto_2
    goto :goto_3

    :cond_2
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v5

    const/4 v6, -0x1

    if-eq v5, v6, :cond_3

    goto :goto_2

    .line 47
    :goto_3
    if-eqz v4, :cond_3

    move-object v5, v4

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    .local v5, "it":I
    const/4 v6, 0x0

    .local v6, "$i$a$-let-ChooserActivity$makeTempCopy$1":I
    if-eqz v1, :cond_3

    const/4 v7, 0x0

    invoke-virtual {v1, v3, v7, v5}, Ljava/io/OutputStream;->write([BII)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 44
    .end local v4    # "len":Ljava/lang/Integer;
    .end local v5    # "it":I
    .end local v6    # "$i$a$-let-ChooserActivity$makeTempCopy$1":I
    :cond_3
    goto :goto_0

    .line 51
    :catch_0
    move-exception v1

    .line 52
    .local v1, "e":Ljava/lang/Exception;
    return-object v0
.end method


# virtual methods
.method public _$_clearFindViewByIdCache()V
    .locals 1

    iget-object v0, p0, Lcom/insecureshop/ChooserActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    :cond_0
    return-void
.end method

.method public _$_findCachedViewById(I)Landroid/view/View;
    .locals 2

    iget-object v0, p0, Lcom/insecureshop/ChooserActivity;->_$_findViewCache:Ljava/util/HashMap;

    if-nez v0, :cond_0

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lcom/insecureshop/ChooserActivity;->_$_findViewCache:Ljava/util/HashMap;

    :cond_0
    iget-object v0, p0, Lcom/insecureshop/ChooserActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    if-nez v0, :cond_1

    invoke-virtual {p0, p1}, Landroidx/fragment/app/FragmentActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    iget-object v1, p0, Lcom/insecureshop/ChooserActivity;->_$_findViewCache:Ljava/util/HashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {v1, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    return-object v0
.end method

.method public final getFilename(Landroid/net/Uri;)Ljava/lang/String;
    .locals 12
    .param p1, "uri"    # Landroid/net/Uri;

    const-string v0, "uri"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkParameterIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    const/4 v0, 0x0

    move-object v1, v0

    check-cast v1, Ljava/lang/String;

    .line 59
    .local v1, "fileName":Ljava/lang/String;
    invoke-virtual {p0}, Lcom/insecureshop/ChooserActivity;->getApplicationContext()Landroid/content/Context;

    move-result-object v2

    .line 60
    .local v2, "context":Landroid/content/Context;
    invoke-virtual {p1}, Landroid/net/Uri;->getScheme()Ljava/lang/String;

    move-result-object v3

    .line 61
    .local v3, "scheme":Ljava/lang/String;
    const-string v4, "file"

    invoke-static {v3, v4}, Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    .line 62
    invoke-virtual {p1}, Landroid/net/Uri;->getLastPathSegment()Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    .line 63
    :cond_0
    const-string v4, "content"

    invoke-static {v3, v4}, Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    .line 64
    nop

    .line 65
    const/4 v4, 0x1

    new-array v7, v4, [Ljava/lang/String;

    const/4 v4, 0x0

    const-string v11, "_display_name"

    aput-object v11, v7, v4

    .line 64
    nop

    .line 66
    .local v7, "proj":[Ljava/lang/String;
    check-cast v0, Landroid/net/Uri;

    .line 67
    .local v0, "contentUri":Landroid/net/Uri;
    const-string v4, "context"

    invoke-static {v2, v4}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v5

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    move-object v6, p1

    invoke-virtual/range {v5 .. v10}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object v4

    .line 68
    .local v4, "cursor":Landroid/database/Cursor;
    if-eqz v4, :cond_1

    invoke-interface {v4}, Landroid/database/Cursor;->getCount()I

    move-result v5

    if-eqz v5, :cond_1

    .line 69
    invoke-interface {v4, v11}, Landroid/database/Cursor;->getColumnIndexOrThrow(Ljava/lang/String;)I

    move-result v5

    .line 70
    .local v5, "columnIndex":I
    invoke-interface {v4}, Landroid/database/Cursor;->moveToFirst()Z

    .line 71
    invoke-interface {v4, v5}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v1

    .line 73
    .end local v0    # "contentUri":Landroid/net/Uri;
    .end local v4    # "cursor":Landroid/database/Cursor;
    .end local v5    # "columnIndex":I
    .end local v7    # "proj":[Ljava/lang/String;
    :cond_1
    :goto_0
    nop

    .line 74
    return-object v1
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .line 20
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V

    .line 21
    const v0, 0x7f0c001e

    invoke-virtual {p0, v0}, Lcom/insecureshop/ChooserActivity;->setContentView(I)V

    .line 22
    invoke-virtual {p0}, Lcom/insecureshop/ChooserActivity;->getIntent()Landroid/content/Intent;

    move-result-object v0

    const-string v1, "intent"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 23
    invoke-virtual {p0}, Lcom/insecureshop/ChooserActivity;->getIntent()Landroid/content/Intent;

    move-result-object v0

    const-string v1, "android.intent.extra.STREAM"

    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    move-result-object v0

    if-eqz v0, :cond_0

    check-cast v0, Landroid/net/Uri;

    .line 24
    .local v0, "uri":Landroid/net/Uri;
    new-instance v1, Ljava/io/File;

    invoke-virtual {v0}, Landroid/net/Uri;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    invoke-static {v1}, Landroid/net/Uri;->fromFile(Ljava/io/File;)Landroid/net/Uri;

    move-result-object v1

    const-string v2, "Uri.fromFile(File(uri.toString()))"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkExpressionValueIsNotNull(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v0, v1

    .line 25
    invoke-virtual {p0, v0}, Lcom/insecureshop/ChooserActivity;->getFilename(Landroid/net/Uri;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {p0, v0, v1}, Lcom/insecureshop/ChooserActivity;->makeTempCopy(Landroid/net/Uri;Ljava/lang/String;)Landroid/net/Uri;

    goto :goto_0

    .line 23
    .end local v0    # "uri":Landroid/net/Uri;
    :cond_0
    new-instance v0, Lkotlin/TypeCastException;

    const-string v1, "null cannot be cast to non-null type android.net.Uri"

    invoke-direct {v0, v1}, Lkotlin/TypeCastException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 28
    :cond_1
    :goto_0
    return-void
.end method
