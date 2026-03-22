.class public Lnet/gotev/uploadservice/MultipartUploadTask;
.super Lnet/gotev/uploadservice/HttpUploadTask;
.source "MultipartUploadTask.java"


# static fields
.field private static final BOUNDARY_SIGNATURE:Ljava/lang/String; = "-------AndroidUploadService"

.field private static final NEW_LINE:Ljava/lang/String; = "\r\n"

.field protected static final PARAM_UTF8_CHARSET:Ljava/lang/String; = "multipartUtf8Charset"

.field protected static final PROPERTY_CONTENT_TYPE:Ljava/lang/String; = "httpContentType"

.field protected static final PROPERTY_PARAM_NAME:Ljava/lang/String; = "httpParamName"

.field protected static final PROPERTY_REMOTE_FILE_NAME:Ljava/lang/String; = "httpRemoteFileName"

.field private static final TWO_HYPHENS:Ljava/lang/String; = "--"

.field private static final US_ASCII:Ljava/nio/charset/Charset;


# instance fields
.field private boundaryBytes:[B

.field private charset:Ljava/nio/charset/Charset;

.field private trailerBytes:[B


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 24
    const-string v0, "US-ASCII"

    invoke-static {v0}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    move-result-object v0

    sput-object v0, Lnet/gotev/uploadservice/MultipartUploadTask;->US_ASCII:Ljava/nio/charset/Charset;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 19
    invoke-direct {p0}, Lnet/gotev/uploadservice/HttpUploadTask;-><init>()V

    return-void
.end method

.method private getFilesLength()J
    .locals 6
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;
        }
    .end annotation

    .line 69
    const-wide/16 v0, 0x0

    .line 71
    .local v0, "total":J
    iget-object v2, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lnet/gotev/uploadservice/UploadFile;

    .line 72
    .local v3, "file":Lnet/gotev/uploadservice/UploadFile;
    invoke-direct {p0, v3}, Lnet/gotev/uploadservice/MultipartUploadTask;->getTotalMultipartBytes(Lnet/gotev/uploadservice/UploadFile;)J

    move-result-wide v4

    add-long/2addr v0, v4

    .line 73
    .end local v3    # "file":Lnet/gotev/uploadservice/UploadFile;
    goto :goto_0

    .line 75
    :cond_0
    return-wide v0
.end method

.method private getMultipartBytes(Lnet/gotev/uploadservice/NameValue;)[B
    .locals 2
    .param p1, "parameter"    # Lnet/gotev/uploadservice/NameValue;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;
        }
    .end annotation

    .line 93
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Content-Disposition: form-data; name=\""

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Lnet/gotev/uploadservice/NameValue;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\""

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\r\n"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    invoke-virtual {p1}, Lnet/gotev/uploadservice/NameValue;->getValue()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->charset:Ljava/nio/charset/Charset;

    invoke-virtual {v0, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v0

    return-object v0
.end method

.method private getMultipartHeader(Lnet/gotev/uploadservice/UploadFile;)[B
    .locals 3
    .param p1, "file"    # Lnet/gotev/uploadservice/UploadFile;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;
        }
    .end annotation

    .line 99
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Content-Disposition: form-data; name=\""

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    const-string v1, "httpParamName"

    invoke-virtual {p1, v1}, Lnet/gotev/uploadservice/UploadFile;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\"; filename=\""

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    const-string v1, "httpRemoteFileName"

    invoke-virtual {p1, v1}, Lnet/gotev/uploadservice/UploadFile;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\""

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\r\n"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "Content-Type: "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    const-string v2, "httpContentType"

    invoke-virtual {p1, v2}, Lnet/gotev/uploadservice/UploadFile;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 105
    .local v0, "header":Ljava/lang/String;
    iget-object v1, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->charset:Ljava/nio/charset/Charset;

    invoke-virtual {v0, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v1

    return-object v1
.end method

.method private getRequestParametersLength()J
    .locals 6
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;
        }
    .end annotation

    .line 79
    const-wide/16 v0, 0x0

    .line 81
    .local v0, "parametersBytes":J
    iget-object v2, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->getRequestParameters()Ljava/util/List;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_0

    .line 82
    iget-object v2, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->getRequestParameters()Ljava/util/List;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lnet/gotev/uploadservice/NameValue;

    .line 85
    .local v3, "parameter":Lnet/gotev/uploadservice/NameValue;
    iget-object v4, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->boundaryBytes:[B

    array-length v4, v4

    invoke-direct {p0, v3}, Lnet/gotev/uploadservice/MultipartUploadTask;->getMultipartBytes(Lnet/gotev/uploadservice/NameValue;)[B

    move-result-object v5

    array-length v5, v5

    add-int/2addr v4, v5

    int-to-long v4, v4

    add-long/2addr v0, v4

    .line 86
    .end local v3    # "parameter":Lnet/gotev/uploadservice/NameValue;
    goto :goto_0

    .line 89
    :cond_0
    return-wide v0
.end method

.method private getTotalMultipartBytes(Lnet/gotev/uploadservice/UploadFile;)J
    .locals 4
    .param p1, "file"    # Lnet/gotev/uploadservice/UploadFile;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;
        }
    .end annotation

    .line 110
    iget-object v0, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->boundaryBytes:[B

    array-length v0, v0

    invoke-direct {p0, p1}, Lnet/gotev/uploadservice/MultipartUploadTask;->getMultipartHeader(Lnet/gotev/uploadservice/UploadFile;)[B

    move-result-object v1

    array-length v1, v1

    add-int/2addr v0, v1

    int-to-long v0, v0

    iget-object v2, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {p1, v2}, Lnet/gotev/uploadservice/UploadFile;->length(Landroid/content/Context;)J

    move-result-wide v2

    add-long/2addr v0, v2

    return-wide v0
.end method

.method private writeFiles(Lnet/gotev/uploadservice/http/BodyWriter;)V
    .locals 7
    .param p1, "bodyWriter"    # Lnet/gotev/uploadservice/http/BodyWriter;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 127
    iget-object v0, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lnet/gotev/uploadservice/UploadFile;

    .line 128
    .local v1, "file":Lnet/gotev/uploadservice/UploadFile;
    iget-boolean v2, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->shouldContinue:Z

    if-nez v2, :cond_0

    .line 129
    goto :goto_1

    .line 131
    :cond_0
    iget-object v2, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->boundaryBytes:[B

    invoke-virtual {p1, v2}, Lnet/gotev/uploadservice/http/BodyWriter;->write([B)V

    .line 132
    invoke-direct {p0, v1}, Lnet/gotev/uploadservice/MultipartUploadTask;->getMultipartHeader(Lnet/gotev/uploadservice/UploadFile;)[B

    move-result-object v2

    .line 133
    .local v2, "headerBytes":[B
    invoke-virtual {p1, v2}, Lnet/gotev/uploadservice/http/BodyWriter;->write([B)V

    .line 135
    iget-wide v3, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->uploadedBytes:J

    iget-object v5, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->boundaryBytes:[B

    array-length v5, v5

    array-length v6, v2

    add-int/2addr v5, v6

    int-to-long v5, v5

    add-long/2addr v3, v5

    iput-wide v3, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->uploadedBytes:J

    .line 136
    iget-wide v3, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->uploadedBytes:J

    iget-wide v5, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->totalBytes:J

    invoke-virtual {p0, v3, v4, v5, v6}, Lnet/gotev/uploadservice/MultipartUploadTask;->broadcastProgress(JJ)V

    .line 138
    iget-object v3, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {v1, v3}, Lnet/gotev/uploadservice/UploadFile;->getStream(Landroid/content/Context;)Ljava/io/InputStream;

    move-result-object v3

    .line 139
    .local v3, "stream":Ljava/io/InputStream;
    invoke-virtual {p1, v3, p0}, Lnet/gotev/uploadservice/http/BodyWriter;->writeStream(Ljava/io/InputStream;Lnet/gotev/uploadservice/http/BodyWriter$OnStreamWriteListener;)V

    .line 140
    invoke-virtual {v3}, Ljava/io/InputStream;->close()V

    .line 141
    .end local v1    # "file":Lnet/gotev/uploadservice/UploadFile;
    .end local v2    # "headerBytes":[B
    .end local v3    # "stream":Ljava/io/InputStream;
    goto :goto_0

    .line 142
    :cond_1
    :goto_1
    return-void
.end method

.method private writeRequestParameters(Lnet/gotev/uploadservice/http/BodyWriter;)V
    .locals 7
    .param p1, "bodyWriter"    # Lnet/gotev/uploadservice/http/BodyWriter;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 114
    iget-object v0, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->getRequestParameters()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_0

    .line 115
    iget-object v0, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->getRequestParameters()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lnet/gotev/uploadservice/NameValue;

    .line 116
    .local v1, "parameter":Lnet/gotev/uploadservice/NameValue;
    iget-object v2, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->boundaryBytes:[B

    invoke-virtual {p1, v2}, Lnet/gotev/uploadservice/http/BodyWriter;->write([B)V

    .line 117
    invoke-direct {p0, v1}, Lnet/gotev/uploadservice/MultipartUploadTask;->getMultipartBytes(Lnet/gotev/uploadservice/NameValue;)[B

    move-result-object v2

    .line 118
    .local v2, "formItemBytes":[B
    invoke-virtual {p1, v2}, Lnet/gotev/uploadservice/http/BodyWriter;->write([B)V

    .line 120
    iget-wide v3, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->uploadedBytes:J

    iget-object v5, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->boundaryBytes:[B

    array-length v5, v5

    array-length v6, v2

    add-int/2addr v5, v6

    int-to-long v5, v5

    add-long/2addr v3, v5

    iput-wide v3, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->uploadedBytes:J

    .line 121
    iget-wide v3, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->uploadedBytes:J

    iget-wide v5, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->totalBytes:J

    invoke-virtual {p0, v3, v4, v5, v6}, Lnet/gotev/uploadservice/MultipartUploadTask;->broadcastProgress(JJ)V

    .line 122
    .end local v1    # "parameter":Lnet/gotev/uploadservice/NameValue;
    .end local v2    # "formItemBytes":[B
    goto :goto_0

    .line 124
    :cond_0
    return-void
.end method


# virtual methods
.method protected getBodyLength()J
    .locals 4
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;
        }
    .end annotation

    .line 58
    invoke-direct {p0}, Lnet/gotev/uploadservice/MultipartUploadTask;->getRequestParametersLength()J

    move-result-wide v0

    invoke-direct {p0}, Lnet/gotev/uploadservice/MultipartUploadTask;->getFilesLength()J

    move-result-wide v2

    add-long/2addr v0, v2

    iget-object v2, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->trailerBytes:[B

    array-length v2, v2

    int-to-long v2, v2

    add-long/2addr v0, v2

    return-wide v0
.end method

.method protected init(Lnet/gotev/uploadservice/UploadService;Landroid/content/Intent;)V
    .locals 5
    .param p1, "service"    # Lnet/gotev/uploadservice/UploadService;
    .param p2, "intent"    # Landroid/content/Intent;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 39
    invoke-super {p0, p1, p2}, Lnet/gotev/uploadservice/HttpUploadTask;->init(Lnet/gotev/uploadservice/UploadService;Landroid/content/Intent;)V

    .line 41
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "-------AndroidUploadService"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 42
    .local v0, "boundary":Ljava/lang/String;
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "\r\n--"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, "\r\n"

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    sget-object v4, Lnet/gotev/uploadservice/MultipartUploadTask;->US_ASCII:Ljava/nio/charset/Charset;

    invoke-virtual {v1, v4}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v1

    iput-object v1, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->boundaryBytes:[B

    .line 43
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "--"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    sget-object v2, Lnet/gotev/uploadservice/MultipartUploadTask;->US_ASCII:Ljava/nio/charset/Charset;

    invoke-virtual {v1, v2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v1

    iput-object v1, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->trailerBytes:[B

    .line 44
    const-string v1, "multipartUtf8Charset"

    const/4 v2, 0x0

    invoke-virtual {p2, v1, v2}, Landroid/content/Intent;->getBooleanExtra(Ljava/lang/String;Z)Z

    move-result v1

    if-eqz v1, :cond_0

    .line 45
    const-string v1, "UTF-8"

    invoke-static {v1}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    move-result-object v1

    goto :goto_0

    :cond_0
    sget-object v1, Lnet/gotev/uploadservice/MultipartUploadTask;->US_ASCII:Ljava/nio/charset/Charset;

    :goto_0
    iput-object v1, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->charset:Ljava/nio/charset/Charset;

    .line 47
    iget-object v1, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    const/4 v2, 0x1

    const-string v3, "Connection"

    if-gt v1, v2, :cond_1

    .line 48
    iget-object v1, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    const-string v2, "close"

    invoke-virtual {v1, v3, v2}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->addRequestHeader(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_1

    .line 50
    :cond_1
    iget-object v1, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    const-string v2, "Keep-Alive"

    invoke-virtual {v1, v3, v2}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->addRequestHeader(Ljava/lang/String;Ljava/lang/String;)V

    .line 53
    :goto_1
    iget-object v1, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "multipart/form-data; boundary="

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    const-string v3, "Content-Type"

    invoke-virtual {v1, v3, v2}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->addRequestHeader(Ljava/lang/String;Ljava/lang/String;)V

    .line 54
    return-void
.end method

.method public onBodyReady(Lnet/gotev/uploadservice/http/BodyWriter;)V
    .locals 1
    .param p1, "bodyWriter"    # Lnet/gotev/uploadservice/http/BodyWriter;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 63
    invoke-direct {p0, p1}, Lnet/gotev/uploadservice/MultipartUploadTask;->writeRequestParameters(Lnet/gotev/uploadservice/http/BodyWriter;)V

    .line 64
    invoke-direct {p0, p1}, Lnet/gotev/uploadservice/MultipartUploadTask;->writeFiles(Lnet/gotev/uploadservice/http/BodyWriter;)V

    .line 65
    iget-object v0, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->trailerBytes:[B

    invoke-virtual {p1, v0}, Lnet/gotev/uploadservice/http/BodyWriter;->write([B)V

    .line 66
    return-void
.end method

.method protected onSuccessfulUpload()V
    .locals 3

    .line 146
    iget-object v0, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lnet/gotev/uploadservice/UploadFile;

    .line 147
    .local v1, "file":Lnet/gotev/uploadservice/UploadFile;
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadFile;->getPath()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p0, v2}, Lnet/gotev/uploadservice/MultipartUploadTask;->addSuccessfullyUploadedFile(Ljava/lang/String;)V

    .line 148
    .end local v1    # "file":Lnet/gotev/uploadservice/UploadFile;
    goto :goto_0

    .line 149
    :cond_0
    iget-object v0, p0, Lnet/gotev/uploadservice/MultipartUploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->clear()V

    .line 150
    return-void
.end method
