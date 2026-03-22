.class public Lnet/gotev/uploadservice/http/impl/HurlStackConnection;
.super Ljava/lang/Object;
.source "HurlStackConnection.java"

# interfaces
.implements Lnet/gotev/uploadservice/http/HttpConnection;


# static fields
.field private static final LOG_TAG:Ljava/lang/String;


# instance fields
.field private mConnection:Ljava/net/HttpURLConnection;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 26
    const-class v0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->LOG_TAG:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;ZZII)V
    .locals 3
    .param p1, "method"    # Ljava/lang/String;
    .param p2, "url"    # Ljava/lang/String;
    .param p3, "followRedirects"    # Z
    .param p4, "useCaches"    # Z
    .param p5, "connectTimeout"    # I
    .param p6, "readTimeout"    # I
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 32
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 33
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "creating new connection"

    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    new-instance v0, Ljava/net/URL;

    invoke-direct {v0, p2}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 37
    .local v0, "urlObj":Ljava/net/URL;
    invoke-virtual {v0}, Ljava/net/URL;->getProtocol()Ljava/lang/String;

    move-result-object v1

    const-string v2, "https"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    .line 38
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v1

    check-cast v1, Ljavax/net/ssl/HttpsURLConnection;

    iput-object v1, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    goto :goto_0

    .line 40
    :cond_0
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v1

    check-cast v1, Ljava/net/HttpURLConnection;

    iput-object v1, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    .line 43
    :goto_0
    iget-object v1, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    const/4 v2, 0x1

    invoke-virtual {v1, v2}, Ljava/net/HttpURLConnection;->setDoInput(Z)V

    .line 44
    iget-object v1, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v1, v2}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    .line 45
    iget-object v1, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v1, p5}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 46
    iget-object v1, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v1, p6}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 47
    iget-object v1, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v1, p4}, Ljava/net/HttpURLConnection;->setUseCaches(Z)V

    .line 48
    iget-object v1, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v1, p3}, Ljava/net/HttpURLConnection;->setInstanceFollowRedirects(Z)V

    .line 49
    iget-object v1, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v1, p1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 50
    return-void
.end method

.method private getResponseBodyAsByteArray(Ljava/io/InputStream;)[B
    .locals 5
    .param p1, "inputStream"    # Ljava/io/InputStream;

    .line 107
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 109
    .local v0, "byteStream":Ljava/io/ByteArrayOutputStream;
    sget v1, Lnet/gotev/uploadservice/UploadService;->BUFFER_SIZE:I

    new-array v1, v1, [B

    .line 113
    .local v1, "buffer":[B
    :goto_0
    :try_start_0
    array-length v2, v1

    const/4 v3, 0x0

    invoke-virtual {p1, v1, v3, v2}, Ljava/io/InputStream;->read([BII)I

    move-result v2

    move v4, v2

    .local v4, "bytesRead":I
    if-lez v2, :cond_0

    .line 114
    invoke-virtual {v0, v1, v3, v4}, Ljava/io/ByteArrayOutputStream;->write([BII)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    .line 116
    :cond_0
    goto :goto_1

    .end local v4    # "bytesRead":I
    :catch_0
    move-exception v2

    .line 118
    :goto_1
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    move-result-object v2

    return-object v2
.end method

.method private getServerResponseBody()[B
    .locals 5
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 84
    const-string v0, "Error while closing server response stream"

    const/4 v1, 0x0

    .line 87
    .local v1, "stream":Ljava/io/InputStream;
    :try_start_0
    iget-object v2, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v2

    div-int/lit8 v2, v2, 0x64

    const/4 v3, 0x2

    if-ne v2, v3, :cond_0

    .line 88
    iget-object v2, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v2

    move-object v1, v2

    goto :goto_0

    .line 90
    :cond_0
    iget-object v2, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    move-result-object v2

    move-object v1, v2

    .line 93
    :goto_0
    invoke-direct {p0, v1}, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->getResponseBodyAsByteArray(Ljava/io/InputStream;)[B

    move-result-object v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 96
    if-eqz v1, :cond_1

    .line 98
    :try_start_1
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 101
    goto :goto_1

    .line 99
    :catch_0
    move-exception v3

    .line 100
    .local v3, "exc":Ljava/lang/Exception;
    sget-object v4, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->LOG_TAG:Ljava/lang/String;

    invoke-static {v4, v0, v3}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 101
    .end local v3    # "exc":Ljava/lang/Exception;
    :cond_1
    :goto_1
    return-object v2

    .line 96
    :catchall_0
    move-exception v2

    if-eqz v1, :cond_2

    .line 98
    :try_start_2
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 101
    goto :goto_2

    .line 99
    :catch_1
    move-exception v3

    .line 100
    .restart local v3    # "exc":Ljava/lang/Exception;
    sget-object v4, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->LOG_TAG:Ljava/lang/String;

    invoke-static {v4, v0, v3}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 101
    .end local v3    # "exc":Ljava/lang/Exception;
    :cond_2
    :goto_2
    throw v2
.end method

.method private getServerResponseHeaders()Ljava/util/LinkedHashMap;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/LinkedHashMap<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 122
    iget-object v0, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getHeaderFields()Ljava/util/Map;

    move-result-object v0

    .line 123
    .local v0, "headers":Ljava/util/Map;, "Ljava/util/Map<Ljava/lang/String;Ljava/util/List<Ljava/lang/String;>;>;"
    if-nez v0, :cond_0

    .line 124
    const/4 v1, 0x0

    return-object v1

    .line 126
    :cond_0
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-interface {v0}, Ljava/util/Map;->size()I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 128
    .local v1, "out":Ljava/util/LinkedHashMap;, "Ljava/util/LinkedHashMap<Ljava/lang/String;Ljava/lang/String;>;"
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    .line 129
    .local v3, "entry":Ljava/util/Map$Entry;, "Ljava/util/Map$Entry<Ljava/lang/String;Ljava/util/List<Ljava/lang/String;>;>;"
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v4

    if-eqz v4, :cond_2

    .line 130
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 131
    .local v4, "headerValue":Ljava/lang/StringBuilder;
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/List;

    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_1
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_1

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    .line 132
    .local v6, "value":Ljava/lang/String;
    invoke-virtual {v4, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 133
    .end local v6    # "value":Ljava/lang/String;
    goto :goto_1

    .line 134
    :cond_1
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v5

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v1, v5, v6}, Ljava/util/LinkedHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 136
    .end local v3    # "entry":Ljava/util/Map$Entry;, "Ljava/util/Map$Entry<Ljava/lang/String;Ljava/util/List<Ljava/lang/String;>;>;"
    .end local v4    # "headerValue":Ljava/lang/StringBuilder;
    :cond_2
    goto :goto_0

    .line 138
    :cond_3
    return-object v1
.end method


# virtual methods
.method public close()V
    .locals 3

    .line 154
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "closing connection"

    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 156
    iget-object v0, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    if-eqz v0, :cond_0

    .line 158
    :try_start_0
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v0

    invoke-virtual {v0}, Ljava/io/InputStream;->close()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    .line 159
    :catch_0
    move-exception v0

    :goto_0
    nop

    .line 162
    :try_start_1
    iget-object v0, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v0

    invoke-virtual {v0}, Ljava/io/OutputStream;->flush()V

    .line 163
    iget-object v0, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v0

    invoke-virtual {v0}, Ljava/io/OutputStream;->close()V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_1

    .line 164
    :catch_1
    move-exception v0

    :goto_1
    nop

    .line 167
    :try_start_2
    iget-object v0, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->disconnect()V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    .line 170
    goto :goto_2

    .line 168
    :catch_2
    move-exception v0

    .line 169
    .local v0, "exc":Ljava/lang/Exception;
    sget-object v1, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->LOG_TAG:Ljava/lang/String;

    const-string v2, "Error while closing connection"

    invoke-static {v1, v2, v0}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 172
    .end local v0    # "exc":Ljava/lang/Exception;
    :cond_0
    :goto_2
    return-void
.end method

.method public getResponse(Lnet/gotev/uploadservice/http/HttpConnection$RequestBodyDelegate;)Lnet/gotev/uploadservice/ServerResponse;
    .locals 5
    .param p1, "delegate"    # Lnet/gotev/uploadservice/http/HttpConnection$RequestBodyDelegate;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 144
    new-instance v0, Lnet/gotev/uploadservice/http/impl/HurlBodyWriter;

    iget-object v1, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v1

    invoke-direct {v0, v1}, Lnet/gotev/uploadservice/http/impl/HurlBodyWriter;-><init>(Ljava/io/OutputStream;)V

    .line 145
    .local v0, "bodyWriter":Lnet/gotev/uploadservice/http/impl/HurlBodyWriter;
    invoke-interface {p1, v0}, Lnet/gotev/uploadservice/http/HttpConnection$RequestBodyDelegate;->onBodyReady(Lnet/gotev/uploadservice/http/BodyWriter;)V

    .line 146
    invoke-virtual {v0}, Lnet/gotev/uploadservice/http/impl/HurlBodyWriter;->flush()V

    .line 148
    new-instance v1, Lnet/gotev/uploadservice/ServerResponse;

    iget-object v2, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v2

    .line 149
    invoke-direct {p0}, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->getServerResponseBody()[B

    move-result-object v3

    invoke-direct {p0}, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->getServerResponseHeaders()Ljava/util/LinkedHashMap;

    move-result-object v4

    invoke-direct {v1, v2, v3, v4}, Lnet/gotev/uploadservice/ServerResponse;-><init>(I[BLjava/util/LinkedHashMap;)V

    return-object v1
.end method

.method public setHeaders(Ljava/util/List;)Lnet/gotev/uploadservice/http/HttpConnection;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lnet/gotev/uploadservice/NameValue;",
            ">;)",
            "Lnet/gotev/uploadservice/http/HttpConnection;"
        }
    .end annotation

    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 54
    .local p1, "requestHeaders":Ljava/util/List;, "Ljava/util/List<Lnet/gotev/uploadservice/NameValue;>;"
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lnet/gotev/uploadservice/NameValue;

    .line 55
    .local v1, "param":Lnet/gotev/uploadservice/NameValue;
    iget-object v2, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/NameValue;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1}, Lnet/gotev/uploadservice/NameValue;->getValue()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v3, v4}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 56
    .end local v1    # "param":Lnet/gotev/uploadservice/NameValue;
    goto :goto_0

    .line 58
    :cond_0
    return-object p0
.end method

.method public setTotalBodyBytes(JZ)Lnet/gotev/uploadservice/http/HttpConnection;
    .locals 3
    .param p1, "totalBodyBytes"    # J
    .param p3, "isFixedLengthStreamingMode"    # Z

    .line 63
    if-eqz p3, :cond_2

    .line 64
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x13

    if-lt v0, v1, :cond_0

    .line 65
    iget-object v0, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    invoke-virtual {v0, p1, p2}, Ljava/net/HttpURLConnection;->setFixedLengthStreamingMode(J)V

    goto :goto_0

    .line 68
    :cond_0
    const-wide/32 v0, 0x7fffffff

    cmp-long v2, p1, v0

    if-gtz v2, :cond_1

    .line 74
    iget-object v0, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    long-to-int v1, p1

    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setFixedLengthStreamingMode(I)V

    goto :goto_0

    .line 69
    :cond_1
    new-instance v0, Ljava/lang/RuntimeException;

    const-string v1, "You need Android API version 19 or newer to upload more than 2GB in a single request using fixed size content length. Try switching to chunked mode instead, but make sure your server side supports it!"

    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 77
    :cond_2
    iget-object v0, p0, Lnet/gotev/uploadservice/http/impl/HurlStackConnection;->mConnection:Ljava/net/HttpURLConnection;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setChunkedStreamingMode(I)V

    .line 80
    :goto_0
    return-object p0
.end method
