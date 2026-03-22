.class public Lnet/gotev/uploadservice/BinaryUploadTask;
.super Lnet/gotev/uploadservice/HttpUploadTask;
.source "BinaryUploadTask.java"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 14
    invoke-direct {p0}, Lnet/gotev/uploadservice/HttpUploadTask;-><init>()V

    return-void
.end method


# virtual methods
.method protected getBodyLength()J
    .locals 2
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;
        }
    .end annotation

    .line 18
    iget-object v0, p0, Lnet/gotev/uploadservice/BinaryUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v0

    const/4 v1, 0x0

    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/UploadFile;

    iget-object v1, p0, Lnet/gotev/uploadservice/BinaryUploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/UploadFile;->length(Landroid/content/Context;)J

    move-result-wide v0

    return-wide v0
.end method

.method public onBodyReady(Lnet/gotev/uploadservice/http/BodyWriter;)V
    .locals 2
    .param p1, "bodyWriter"    # Lnet/gotev/uploadservice/http/BodyWriter;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 23
    iget-object v0, p0, Lnet/gotev/uploadservice/BinaryUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v0

    const/4 v1, 0x0

    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/UploadFile;

    iget-object v1, p0, Lnet/gotev/uploadservice/BinaryUploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/UploadFile;->getStream(Landroid/content/Context;)Ljava/io/InputStream;

    move-result-object v0

    invoke-virtual {p1, v0, p0}, Lnet/gotev/uploadservice/http/BodyWriter;->writeStream(Ljava/io/InputStream;Lnet/gotev/uploadservice/http/BodyWriter$OnStreamWriteListener;)V

    .line 24
    return-void
.end method

.method protected onSuccessfulUpload()V
    .locals 2

    .line 28
    iget-object v0, p0, Lnet/gotev/uploadservice/BinaryUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v0

    const/4 v1, 0x0

    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/UploadFile;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadFile;->getPath()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v0}, Lnet/gotev/uploadservice/BinaryUploadTask;->addSuccessfullyUploadedFile(Ljava/lang/String;)V

    .line 29
    iget-object v0, p0, Lnet/gotev/uploadservice/BinaryUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->clear()V

    .line 30
    return-void
.end method
