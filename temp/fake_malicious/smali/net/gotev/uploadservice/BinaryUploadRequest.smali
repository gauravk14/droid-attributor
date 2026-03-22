.class public Lnet/gotev/uploadservice/BinaryUploadRequest;
.super Lnet/gotev/uploadservice/HttpUploadRequest;
.source "BinaryUploadRequest.java"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lnet/gotev/uploadservice/HttpUploadRequest<",
        "Lnet/gotev/uploadservice/BinaryUploadRequest;",
        ">;"
    }
.end annotation


# direct methods
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

    .line 50
    const/4 v0, 0x0

    invoke-direct {p0, p1, v0, p2}, Lnet/gotev/uploadservice/BinaryUploadRequest;-><init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V

    .line 51
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "uploadId"    # Ljava/lang/String;
    .param p3, "serverUrl"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/IllegalArgumentException;,
            Ljava/net/MalformedURLException;
        }
    .end annotation

    .line 35
    invoke-direct {p0, p1, p2, p3}, Lnet/gotev/uploadservice/HttpUploadRequest;-><init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    return-void
.end method

.method private logDoesNotSupportParameters()V
    .locals 2

    .line 98
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "This upload method does not support adding parameters"

    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;)V

    .line 100
    return-void
.end method


# virtual methods
.method public addArrayParameter(Ljava/lang/String;Ljava/util/List;)Lnet/gotev/uploadservice/BinaryUploadRequest;
    .locals 0
    .param p1, "paramName"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)",
            "Lnet/gotev/uploadservice/BinaryUploadRequest;"
        }
    .end annotation

    .line 85
    .local p2, "list":Ljava/util/List;, "Ljava/util/List<Ljava/lang/String;>;"
    invoke-direct {p0}, Lnet/gotev/uploadservice/BinaryUploadRequest;->logDoesNotSupportParameters()V

    .line 86
    return-object p0
.end method

.method public varargs addArrayParameter(Ljava/lang/String;[Ljava/lang/String;)Lnet/gotev/uploadservice/BinaryUploadRequest;
    .locals 0
    .param p1, "paramName"    # Ljava/lang/String;
    .param p2, "array"    # [Ljava/lang/String;

    .line 79
    invoke-direct {p0}, Lnet/gotev/uploadservice/BinaryUploadRequest;->logDoesNotSupportParameters()V

    .line 80
    return-object p0
.end method

.method public bridge synthetic addArrayParameter(Ljava/lang/String;Ljava/util/List;)Lnet/gotev/uploadservice/HttpUploadRequest;
    .locals 0

    .line 16
    invoke-virtual {p0, p1, p2}, Lnet/gotev/uploadservice/BinaryUploadRequest;->addArrayParameter(Ljava/lang/String;Ljava/util/List;)Lnet/gotev/uploadservice/BinaryUploadRequest;

    move-result-object p1

    return-object p1
.end method

.method public bridge synthetic addArrayParameter(Ljava/lang/String;[Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadRequest;
    .locals 0

    .line 16
    invoke-virtual {p0, p1, p2}, Lnet/gotev/uploadservice/BinaryUploadRequest;->addArrayParameter(Ljava/lang/String;[Ljava/lang/String;)Lnet/gotev/uploadservice/BinaryUploadRequest;

    move-result-object p1

    return-object p1
.end method

.method public addParameter(Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/BinaryUploadRequest;
    .locals 0
    .param p1, "paramName"    # Ljava/lang/String;
    .param p2, "paramValue"    # Ljava/lang/String;

    .line 73
    invoke-direct {p0}, Lnet/gotev/uploadservice/BinaryUploadRequest;->logDoesNotSupportParameters()V

    .line 74
    return-object p0
.end method

.method public bridge synthetic addParameter(Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadRequest;
    .locals 0

    .line 16
    invoke-virtual {p0, p1, p2}, Lnet/gotev/uploadservice/BinaryUploadRequest;->addParameter(Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/BinaryUploadRequest;

    move-result-object p1

    return-object p1
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

    .line 55
    const-class v0, Lnet/gotev/uploadservice/BinaryUploadTask;

    return-object v0
.end method

.method public setFileToUpload(Ljava/lang/String;)Lnet/gotev/uploadservice/BinaryUploadRequest;
    .locals 2
    .param p1, "path"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/FileNotFoundException;
        }
    .end annotation

    .line 66
    iget-object v0, p0, Lnet/gotev/uploadservice/BinaryUploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->clear()V

    .line 67
    iget-object v0, p0, Lnet/gotev/uploadservice/BinaryUploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    new-instance v1, Lnet/gotev/uploadservice/UploadFile;

    invoke-direct {v1, p1}, Lnet/gotev/uploadservice/UploadFile;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->addFile(Lnet/gotev/uploadservice/UploadFile;)V

    .line 68
    return-object p0
.end method

.method public startUpload()Ljava/lang/String;
    .locals 2

    .line 91
    iget-object v0, p0, Lnet/gotev/uploadservice/BinaryUploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_0

    .line 94
    invoke-super {p0}, Lnet/gotev/uploadservice/HttpUploadRequest;->startUpload()Ljava/lang/String;

    move-result-object v0

    return-object v0

    .line 92
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Set the file to be used in the request body first!"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
