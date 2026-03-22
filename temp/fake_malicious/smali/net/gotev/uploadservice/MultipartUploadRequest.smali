.class public Lnet/gotev/uploadservice/MultipartUploadRequest;
.super Lnet/gotev/uploadservice/HttpUploadRequest;
.source "MultipartUploadRequest.java"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lnet/gotev/uploadservice/HttpUploadRequest<",
        "Lnet/gotev/uploadservice/MultipartUploadRequest;",
        ">;"
    }
.end annotation


# static fields
.field private static final LOG_TAG:Ljava/lang/String;


# instance fields
.field private isUtf8Charset:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 20
    const-class v0, Lnet/gotev/uploadservice/MultipartUploadRequest;

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Lnet/gotev/uploadservice/MultipartUploadRequest;->LOG_TAG:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;)V
    .locals 1
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "serverUrl"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/net/MalformedURLException;,
            Ljava/lang/IllegalArgumentException;
        }
    .end annotation

    .line 55
    const/4 v0, 0x0

    invoke-direct {p0, p1, v0, p2}, Lnet/gotev/uploadservice/MultipartUploadRequest;-><init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V

    .line 56
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "uploadId"    # Ljava/lang/String;
    .param p3, "serverUrl"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/IllegalArgumentException;,
            Ljava/net/MalformedURLException;
        }
    .end annotation

    .line 40
    invoke-direct {p0, p1, p2, p3}, Lnet/gotev/uploadservice/HttpUploadRequest;-><init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V

    .line 21
    const/4 v0, 0x0

    iput-boolean v0, p0, Lnet/gotev/uploadservice/MultipartUploadRequest;->isUtf8Charset:Z

    .line 41
    return-void
.end method


# virtual methods
.method public addFileToUpload(Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/MultipartUploadRequest;
    .locals 1
    .param p1, "path"    # Ljava/lang/String;
    .param p2, "parameterName"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/FileNotFoundException;,
            Ljava/lang/IllegalArgumentException;
        }
    .end annotation

    .line 155
    const/4 v0, 0x0

    invoke-virtual {p0, p1, p2, v0, v0}, Lnet/gotev/uploadservice/MultipartUploadRequest;->addFileToUpload(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/MultipartUploadRequest;

    move-result-object v0

    return-object v0
.end method

.method public addFileToUpload(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/MultipartUploadRequest;
    .locals 1
    .param p1, "path"    # Ljava/lang/String;
    .param p2, "parameterName"    # Ljava/lang/String;
    .param p3, "fileName"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/FileNotFoundException;,
            Ljava/lang/IllegalArgumentException;
        }
    .end annotation

    .line 138
    const/4 v0, 0x0

    invoke-virtual {p0, p1, p2, p3, v0}, Lnet/gotev/uploadservice/MultipartUploadRequest;->addFileToUpload(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/MultipartUploadRequest;

    move-result-object v0

    return-object v0
.end method

.method public addFileToUpload(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/MultipartUploadRequest;
    .locals 6
    .param p1, "filePath"    # Ljava/lang/String;
    .param p2, "parameterName"    # Ljava/lang/String;
    .param p3, "fileName"    # Ljava/lang/String;
    .param p4, "contentType"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/FileNotFoundException;,
            Ljava/lang/IllegalArgumentException;
        }
    .end annotation

    .line 89
    new-instance v0, Lnet/gotev/uploadservice/UploadFile;

    invoke-direct {v0, p1}, Lnet/gotev/uploadservice/UploadFile;-><init>(Ljava/lang/String;)V

    .line 90
    .local v0, "file":Lnet/gotev/uploadservice/UploadFile;
    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadFile;->getPath()Ljava/lang/String;

    move-result-object p1

    .line 92
    if-eqz p2, :cond_4

    const-string v1, ""

    invoke-virtual {v1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_4

    .line 97
    const-string v2, "httpParamName"

    invoke-virtual {v0, v2, p2}, Lnet/gotev/uploadservice/UploadFile;->setProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 99
    const-string v2, " is: "

    if-eqz p4, :cond_1

    invoke-virtual {p4}, Ljava/lang/String;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_0

    goto :goto_0

    .line 104
    :cond_0
    sget-object v3, Lnet/gotev/uploadservice/MultipartUploadRequest;->LOG_TAG:Ljava/lang/String;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "Content Type set for "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v3, v2}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_1

    .line 100
    :cond_1
    :goto_0
    iget-object v3, p0, Lnet/gotev/uploadservice/MultipartUploadRequest;->context:Landroid/content/Context;

    invoke-virtual {v0, v3}, Lnet/gotev/uploadservice/UploadFile;->getContentType(Landroid/content/Context;)Ljava/lang/String;

    move-result-object p4

    .line 101
    sget-object v3, Lnet/gotev/uploadservice/MultipartUploadRequest;->LOG_TAG:Ljava/lang/String;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "Auto-detected MIME type for "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v3, v2}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 108
    :goto_1
    const-string v2, "httpContentType"

    invoke-virtual {v0, v2, p4}, Lnet/gotev/uploadservice/UploadFile;->setProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 110
    if-eqz p3, :cond_3

    invoke-virtual {v1, p3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    goto :goto_2

    .line 114
    :cond_2
    sget-object v1, Lnet/gotev/uploadservice/MultipartUploadRequest;->LOG_TAG:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Using custom file name: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_3

    .line 111
    :cond_3
    :goto_2
    iget-object v1, p0, Lnet/gotev/uploadservice/MultipartUploadRequest;->context:Landroid/content/Context;

    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/UploadFile;->getName(Landroid/content/Context;)Ljava/lang/String;

    move-result-object p3

    .line 112
    sget-object v1, Lnet/gotev/uploadservice/MultipartUploadRequest;->LOG_TAG:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Using original file name: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 117
    :goto_3
    const-string v1, "httpRemoteFileName"

    invoke-virtual {v0, v1, p3}, Lnet/gotev/uploadservice/UploadFile;->setProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 119
    iget-object v1, p0, Lnet/gotev/uploadservice/MultipartUploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1, v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->addFile(Lnet/gotev/uploadservice/UploadFile;)V

    .line 120
    return-object p0

    .line 93
    :cond_4
    new-instance v1, Ljava/lang/IllegalArgumentException;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Please specify parameterName value for file: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1
.end method

.method protected getTaskClass()Ljava/lang/Class;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/lang/Class<",
            "+",
            "Lnet/gotev/uploadservice/UploadTask;",
            ">;"
        }
    .end annotation

    .line 66
    const-class v0, Lnet/gotev/uploadservice/MultipartUploadTask;

    return-object v0
.end method

.method protected initializeIntent(Landroid/content/Intent;)V
    .locals 2
    .param p1, "intent"    # Landroid/content/Intent;

    .line 60
    invoke-super {p0, p1}, Lnet/gotev/uploadservice/HttpUploadRequest;->initializeIntent(Landroid/content/Intent;)V

    .line 61
    iget-boolean v0, p0, Lnet/gotev/uploadservice/MultipartUploadRequest;->isUtf8Charset:Z

    const-string v1, "multipartUtf8Charset"

    invoke-virtual {p1, v1, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Z)Landroid/content/Intent;

    .line 62
    return-void
.end method

.method public setUtf8Charset()Lnet/gotev/uploadservice/MultipartUploadRequest;
    .locals 1

    .line 164
    const/4 v0, 0x1

    iput-boolean v0, p0, Lnet/gotev/uploadservice/MultipartUploadRequest;->isUtf8Charset:Z

    .line 165
    return-object p0
.end method
