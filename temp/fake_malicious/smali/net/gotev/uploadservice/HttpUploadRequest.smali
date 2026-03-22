.class public abstract Lnet/gotev/uploadservice/HttpUploadRequest;
.super Lnet/gotev/uploadservice/UploadRequest;
.source "HttpUploadRequest.java"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<B:",
        "Lnet/gotev/uploadservice/HttpUploadRequest<",
        "TB;>;>",
        "Lnet/gotev/uploadservice/UploadRequest<",
        "TB;>;"
    }
.end annotation


# instance fields
.field protected final httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "uploadId"    # Ljava/lang/String;
    .param p3, "serverUrl"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/net/MalformedURLException;,
            Ljava/lang/IllegalArgumentException;
        }
    .end annotation

    .line 37
    .local p0, "this":Lnet/gotev/uploadservice/HttpUploadRequest;, "Lnet/gotev/uploadservice/HttpUploadRequest<TB;>;"
    invoke-direct {p0, p1, p2, p3}, Lnet/gotev/uploadservice/UploadRequest;-><init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V

    .line 22
    new-instance v0, Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-direct {v0}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    .line 39
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getServerUrl()Ljava/lang/String;

    move-result-object v0

    const-string v1, "http://"

    invoke-virtual {v0, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 40
    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getServerUrl()Ljava/lang/String;

    move-result-object v0

    const-string v1, "https://"

    invoke-virtual {v0, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 41
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Specify either http:// or https:// as protocol"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 45
    :cond_1
    :goto_0
    new-instance v0, Ljava/net/URL;

    iget-object v1, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getServerUrl()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 46
    return-void
.end method


# virtual methods
.method public addArrayParameter(Ljava/lang/String;Ljava/util/List;)Lnet/gotev/uploadservice/HttpUploadRequest;
    .locals 3
    .param p1, "paramName"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)TB;"
        }
    .end annotation

    .line 112
    .local p0, "this":Lnet/gotev/uploadservice/HttpUploadRequest;, "Lnet/gotev/uploadservice/HttpUploadRequest<TB;>;"
    .local p2, "list":Ljava/util/List;, "Ljava/util/List<Ljava/lang/String;>;"
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    .line 113
    .local v1, "value":Ljava/lang/String;
    iget-object v2, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v2, p1, v1}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->addRequestParameter(Ljava/lang/String;Ljava/lang/String;)V

    .line 114
    .end local v1    # "value":Ljava/lang/String;
    goto :goto_0

    .line 115
    :cond_0
    invoke-virtual {p0}, Lnet/gotev/uploadservice/HttpUploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/HttpUploadRequest;

    return-object v0
.end method

.method public varargs addArrayParameter(Ljava/lang/String;[Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadRequest;
    .locals 4
    .param p1, "paramName"    # Ljava/lang/String;
    .param p2, "array"    # [Ljava/lang/String;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "[",
            "Ljava/lang/String;",
            ")TB;"
        }
    .end annotation

    .line 98
    .local p0, "this":Lnet/gotev/uploadservice/HttpUploadRequest;, "Lnet/gotev/uploadservice/HttpUploadRequest<TB;>;"
    array-length v0, p2

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    aget-object v2, p2, v1

    .line 99
    .local v2, "value":Ljava/lang/String;
    iget-object v3, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v3, p1, v2}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->addRequestParameter(Ljava/lang/String;Ljava/lang/String;)V

    .line 98
    .end local v2    # "value":Ljava/lang/String;
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 101
    :cond_0
    invoke-virtual {p0}, Lnet/gotev/uploadservice/HttpUploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/HttpUploadRequest;

    return-object v0
.end method

.method public addHeader(Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadRequest;
    .locals 1
    .param p1, "headerName"    # Ljava/lang/String;
    .param p2, "headerValue"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ")TB;"
        }
    .end annotation

    .line 62
    .local p0, "this":Lnet/gotev/uploadservice/HttpUploadRequest;, "Lnet/gotev/uploadservice/HttpUploadRequest<TB;>;"
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v0, p1, p2}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->addRequestHeader(Ljava/lang/String;Ljava/lang/String;)V

    .line 63
    invoke-virtual {p0}, Lnet/gotev/uploadservice/HttpUploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/HttpUploadRequest;

    return-object v0
.end method

.method public addParameter(Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadRequest;
    .locals 1
    .param p1, "paramName"    # Ljava/lang/String;
    .param p2, "paramValue"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ")TB;"
        }
    .end annotation

    .line 86
    .local p0, "this":Lnet/gotev/uploadservice/HttpUploadRequest;, "Lnet/gotev/uploadservice/HttpUploadRequest<TB;>;"
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v0, p1, p2}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->addRequestParameter(Ljava/lang/String;Ljava/lang/String;)V

    .line 87
    invoke-virtual {p0}, Lnet/gotev/uploadservice/HttpUploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/HttpUploadRequest;

    return-object v0
.end method

.method protected initializeIntent(Landroid/content/Intent;)V
    .locals 2
    .param p1, "intent"    # Landroid/content/Intent;

    .line 50
    .local p0, "this":Lnet/gotev/uploadservice/HttpUploadRequest;, "Lnet/gotev/uploadservice/HttpUploadRequest<TB;>;"
    invoke-super {p0, p1}, Lnet/gotev/uploadservice/UploadRequest;->initializeIntent(Landroid/content/Intent;)V

    .line 51
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    const-string v1, "httpTaskParameters"

    invoke-virtual {p1, v1, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 52
    return-void
.end method

.method public setBasicAuth(Ljava/lang/String;Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadRequest;
    .locals 4
    .param p1, "username"    # Ljava/lang/String;
    .param p2, "password"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ")TB;"
        }
    .end annotation

    .line 73
    .local p0, "this":Lnet/gotev/uploadservice/HttpUploadRequest;, "Lnet/gotev/uploadservice/HttpUploadRequest<TB;>;"
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ":"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B

    move-result-object v0

    const/4 v1, 0x2

    invoke-static {v0, v1}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    move-result-object v0

    .line 74
    .local v0, "auth":Ljava/lang/String;
    iget-object v1, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Basic "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    const-string v3, "Authorization"

    invoke-virtual {v1, v3, v2}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->addRequestHeader(Ljava/lang/String;Ljava/lang/String;)V

    .line 75
    invoke-virtual {p0}, Lnet/gotev/uploadservice/HttpUploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v1

    check-cast v1, Lnet/gotev/uploadservice/HttpUploadRequest;

    return-object v1
.end method

.method public setCustomUserAgent(Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadRequest;
    .locals 1
    .param p1, "customUserAgent"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")TB;"
        }
    .end annotation

    .line 138
    .local p0, "this":Lnet/gotev/uploadservice/HttpUploadRequest;, "Lnet/gotev/uploadservice/HttpUploadRequest<TB;>;"
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v0, p1}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->setCustomUserAgent(Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    .line 139
    invoke-virtual {p0}, Lnet/gotev/uploadservice/HttpUploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/HttpUploadRequest;

    return-object v0
.end method

.method public setMethod(Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadRequest;
    .locals 1
    .param p1, "method"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")TB;"
        }
    .end annotation

    .line 125
    .local p0, "this":Lnet/gotev/uploadservice/HttpUploadRequest;, "Lnet/gotev/uploadservice/HttpUploadRequest<TB;>;"
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v0, p1}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->setMethod(Ljava/lang/String;)Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    .line 126
    invoke-virtual {p0}, Lnet/gotev/uploadservice/HttpUploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/HttpUploadRequest;

    return-object v0
.end method

.method public setUsesFixedLengthStreamingMode(Z)Lnet/gotev/uploadservice/HttpUploadRequest;
    .locals 1
    .param p1, "fixedLength"    # Z
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z)TB;"
        }
    .end annotation

    .line 152
    .local p0, "this":Lnet/gotev/uploadservice/HttpUploadRequest;, "Lnet/gotev/uploadservice/HttpUploadRequest<TB;>;"
    iget-object v0, p0, Lnet/gotev/uploadservice/HttpUploadRequest;->httpParams:Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    invoke-virtual {v0, p1}, Lnet/gotev/uploadservice/HttpUploadTaskParameters;->setUsesFixedLengthStreamingMode(Z)Lnet/gotev/uploadservice/HttpUploadTaskParameters;

    .line 153
    invoke-virtual {p0}, Lnet/gotev/uploadservice/HttpUploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/HttpUploadRequest;

    return-object v0
.end method
