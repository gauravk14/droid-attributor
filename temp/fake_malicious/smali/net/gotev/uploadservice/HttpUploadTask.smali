.class public abstract Lnet/gotev/uploadservice/HttpUploadTask;
.super Lnet/gotev/uploadservice/UploadTask;
.source "HttpUploadTask.java"

# interfaces
.implements Lnet/gotev/uploadservice/http/HttpConnection$RequestBodyDelegate;
.implements Lnet/gotev/uploadservice/http/BodyWriter$OnStreamWriteListener;


# static fields
.field private static final LOG_TAG:Ljava/lang/String;


# instance fields
.field private connection:Lnet/gotev/uploadservice/http/HttpConnection;

.field protected httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 23
    const-class v0, Lnet/gotev/uploadservice/HttpUploadTask;

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Lnet/gotev/uploadservice/HttpUploadTask;->LOG_TAG:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 20
    invoke-direct {p0}, Lnet/gotev/uploadservice/UploadTask;-><init>()V

    .line 28
    const/4 v0, 0x0

    iput-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    return-void
.end method


# virtual methods
.method protected abstract getBodyLength()J
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;
        }
    .end annotation
.end method

.method protected init(Lnet/gotev/uploadservice/UploadService;Landroid/content/Intent;)V
    .locals 1
    .param p1, "service"    # Lnet/gotev/uploadservice/UploadService;
    .param p2, "intent"    # Landroid/content/Intent;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 37
    invoke-super {p0, p1, p2}, Lnet/gotev/uploadservice/UploadTask;->init(Lnet/gotev/uploadservice/UploadService;Landroid/content/Intent;)V

    .line 38
    const-string v0, "httpTaskParameters"

    invoke-virtual {p2, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    iput-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    .line 39
    return-void
.end method

.method public onBytesWritten(I)V
    .locals 4
    .param p1, "bytesWritten"    # I

    .line 106
    iget-wide v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->uploadedBytes:J

    int-to-long v2, p1

    add-long/2addr v0, v2

    iput-wide v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->uploadedBytes:J

    .line 107
    iget-wide v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->uploadedBytes:J

    iget-wide v2, p0, Lnet/gotev/uploadservice/HttpUploadTask;->totalBytes:J

    invoke-virtual {p0, v0, v1, v2, v3}, Lnet/gotev/uploadservice/HttpUploadTask;->broadcastProgress(JJ)V

    .line 108
    return-void
.end method

.method public shouldContinueWriting()Z
    .locals 1

    .line 101
    iget-boolean v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->shouldContinue:Z

    return v0
.end method

.method protected upload()V
    .locals 4
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    .line 54
    sget-object v0, Lnet/gotev/uploadservice/HttpUploadTask;->LOG_TAG:Ljava/lang/String;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Starting upload task with ID "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Lnet/gotev/uploadservice/HttpUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 57
    :try_start_0
    invoke-virtual {p0}, Lnet/gotev/uploadservice/HttpUploadTask;->getSuccessfullyUploadedFiles()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->clear()V

    .line 58
    const-wide/16 v0, 0x0

    iput-wide v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->uploadedBytes:J

    .line 59
    invoke-virtual {p0}, Lnet/gotev/uploadservice/HttpUploadTask;->getBodyLength()J

    move-result-wide v0

    iput-wide v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->totalBytes:J

    .line 61
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->isCustomUserAgentDefined()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 62
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    const-string v1, "User-Agent"

    iget-object v2, p0, Lnet/gotev/uploadservice/HttpUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->getCustomUserAgent()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->addRequestHeader(Ljava/lang/String;Ljava/lang/String;)V

    .line 65
    :cond_0
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->HTTP_STACK:Lnet/gotev/uploadservice/http/HttpStack;

    iget-object v1, p0, Lnet/gotev/uploadservice/HttpUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    .line 66
    invoke-virtual {v1}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->getMethod()Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Lnet/gotev/uploadservice/HttpUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getServerUrl()Ljava/lang/String;

    move-result-object v2

    invoke-interface {v0, v1, v2}, Lnet/gotev/uploadservice/http/HttpStack;->createNewConnection(Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/http/HttpConnection;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/HttpUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    .line 67
    invoke-virtual {v1}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->getRequestHeaders()Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Lnet/gotev/uploadservice/http/HttpConnection;->setHeaders(Ljava/util/List;)Lnet/gotev/uploadservice/http/HttpConnection;

    move-result-object v0

    iget-wide v1, p0, Lnet/gotev/uploadservice/HttpUploadTask;->totalBytes:J

    iget-object v3, p0, Lnet/gotev/uploadservice/HttpUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    .line 68
    invoke-virtual {v3}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->isUsesFixedLengthStreamingMode()Z

    move-result v3

    invoke-interface {v0, v1, v2, v3}, Lnet/gotev/uploadservice/http/HttpConnection;->setTotalBodyBytes(JZ)Lnet/gotev/uploadservice/http/HttpConnection;

    move-result-object v0

    iput-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->connection:Lnet/gotev/uploadservice/http/HttpConnection;

    .line 70
    invoke-interface {v0, p0}, Lnet/gotev/uploadservice/http/HttpConnection;->getResponse(Lnet/gotev/uploadservice/http/HttpConnection$RequestBodyDelegate;)Lnet/gotev/uploadservice/ServerResponse;

    move-result-object v0

    .line 71
    .local v0, "response":Lnet/gotev/uploadservice/ServerResponse;
    sget-object v1, Lnet/gotev/uploadservice/HttpUploadTask;->LOG_TAG:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Server responded with HTTP "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/ServerResponse;->getHttpCode()I

    move-result v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, " to upload with ID: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v3, p0, Lnet/gotev/uploadservice/HttpUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 72
    invoke-virtual {v3}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    .line 71
    invoke-static {v1, v2}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 80
    iget-boolean v1, p0, Lnet/gotev/uploadservice/HttpUploadTask;->shouldContinue:Z

    if-eqz v1, :cond_1

    .line 81
    invoke-virtual {p0, v0}, Lnet/gotev/uploadservice/HttpUploadTask;->broadcastCompleted(Lnet/gotev/uploadservice/ServerResponse;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 85
    .end local v0    # "response":Lnet/gotev/uploadservice/ServerResponse;
    :cond_1
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadTask;->connection:Lnet/gotev/uploadservice/http/HttpConnection;

    if-eqz v0, :cond_2

    .line 86
    invoke-interface {v0}, Lnet/gotev/uploadservice/http/HttpConnection;->close()V

    .line 88
    :cond_2
    return-void

    .line 85
    :catchall_0
    move-exception v0

    iget-object v1, p0, Lnet/gotev/uploadservice/HttpUploadTask;->connection:Lnet/gotev/uploadservice/http/HttpConnection;

    if-eqz v1, :cond_3

    .line 86
    invoke-interface {v1}, Lnet/gotev/uploadservice/http/HttpConnection;->close()V

    :cond_3
    throw v0
.end method
