.class Lnet/gotev/uploadservice/schemehandlers/ContentSchemeHandler;
.super Ljava/lang/Object;
.source "ContentSchemeHandler.java"

# interfaces
.implements Lnet/gotev/uploadservice/schemehandlers/SchemeHandler;


# instance fields
.field private uri:Landroid/net/Uri;


# direct methods
.method constructor <init>()V
    .locals 0

    .line 20
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private getUriName(Landroid/content/Context;)Ljava/lang/String;
    .locals 6
    .param p1, "context"    # Landroid/content/Context;

    .line 67
    invoke-virtual {p1}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/schemehandlers/ContentSchemeHandler;->uri:Landroid/net/Uri;

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-virtual/range {v0 .. v5}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object v0

    .line 68
    .local v0, "cursor":Landroid/database/Cursor;
    if-nez v0, :cond_0

    .line 69
    invoke-direct {p0}, Lnet/gotev/uploadservice/schemehandlers/ContentSchemeHandler;->getUriNameFallback()Ljava/lang/String;

    move-result-object v1

    return-object v1

    .line 71
    :cond_0
    const-string v1, "_display_name"

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    .line 72
    .local v1, "nameIndex":I
    invoke-interface {v0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 73
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v2

    .line 74
    .local v2, "name":Ljava/lang/String;
    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    .line 75
    return-object v2
.end method

.method private getUriNameFallback()Ljava/lang/String;
    .locals 2

    .line 79
    iget-object v0, p0, Lnet/gotev/uploadservice/schemehandlers/ContentSchemeHandler;->uri:Landroid/net/Uri;

    invoke-virtual {v0}, Landroid/net/Uri;->toString()Ljava/lang/String;

    move-result-object v0

    sget-object v1, Ljava/io/File;->separator:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v0

    .line 80
    .local v0, "components":[Ljava/lang/String;
    array-length v1, v0

    add-int/lit8 v1, v1, -0x1

    aget-object v1, v0, v1

    return-object v1
.end method

.method private getUriSize(Landroid/content/Context;)J
    .locals 6
    .param p1, "context"    # Landroid/content/Context;

    .line 54
    invoke-virtual {p1}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/schemehandlers/ContentSchemeHandler;->uri:Landroid/net/Uri;

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-virtual/range {v0 .. v5}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object v0

    .line 55
    .local v0, "cursor":Landroid/database/Cursor;
    if-nez v0, :cond_0

    .line 56
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "null cursor for "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v3, p0, Lnet/gotev/uploadservice/schemehandlers/ContentSchemeHandler;->uri:Landroid/net/Uri;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, ", returning size 0"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;)V

    .line 57
    const-wide/16 v1, 0x0

    return-wide v1

    .line 59
    :cond_0
    const-string v1, "_size"

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    .line 60
    .local v1, "sizeIndex":I
    invoke-interface {v0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 61
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v2

    .line 62
    .local v2, "size":J
    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    .line 63
    return-wide v2
.end method


# virtual methods
.method public getContentType(Landroid/content/Context;)Ljava/lang/String;
    .locals 2
    .param p1, "context"    # Landroid/content/Context;

    .line 41
    invoke-virtual {p1}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/schemehandlers/ContentSchemeHandler;->uri:Landroid/net/Uri;

    invoke-virtual {v0, v1}, Landroid/content/ContentResolver;->getType(Landroid/net/Uri;)Ljava/lang/String;

    move-result-object v0

    .line 42
    .local v0, "type":Ljava/lang/String;
    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_1

    .line 43
    :cond_0
    const-string v0, "application/octet-stream"

    .line 45
    :cond_1
    return-object v0
.end method

.method public getInputStream(Landroid/content/Context;)Ljava/io/InputStream;
    .locals 2
    .param p1, "context"    # Landroid/content/Context;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/FileNotFoundException;
        }
    .end annotation

    .line 36
    invoke-virtual {p1}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/schemehandlers/ContentSchemeHandler;->uri:Landroid/net/Uri;

    invoke-virtual {v0, v1}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;

    move-result-object v0

    return-object v0
.end method

.method public getLength(Landroid/content/Context;)J
    .locals 2
    .param p1, "context"    # Landroid/content/Context;

    .line 31
    invoke-direct {p0, p1}, Lnet/gotev/uploadservice/schemehandlers/ContentSchemeHandler;->getUriSize(Landroid/content/Context;)J

    move-result-wide v0

    return-wide v0
.end method

.method public getName(Landroid/content/Context;)Ljava/lang/String;
    .locals 1
    .param p1, "context"    # Landroid/content/Context;

    .line 50
    invoke-direct {p0, p1}, Lnet/gotev/uploadservice/schemehandlers/ContentSchemeHandler;->getUriName(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public init(Ljava/lang/String;)V
    .locals 1
    .param p1, "path"    # Ljava/lang/String;

    .line 26
    invoke-static {p1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/schemehandlers/ContentSchemeHandler;->uri:Landroid/net/Uri;

    .line 27
    return-void
.end method
