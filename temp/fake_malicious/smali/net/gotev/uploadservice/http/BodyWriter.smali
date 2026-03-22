.class public abstract Lnet/gotev/uploadservice/http/BodyWriter;
.super Ljava/lang/Object;
.source "BodyWriter.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lnet/gotev/uploadservice/http/BodyWriter$OnStreamWriteListener;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    return-void
.end method


# virtual methods
.method public abstract flush()V
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation
.end method

.method public abstract write([B)V
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation
.end method

.method public abstract write([BI)V
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation
.end method

.method public final writeStream(Ljava/io/InputStream;Lnet/gotev/uploadservice/http/BodyWriter$OnStreamWriteListener;)V
    .locals 3
    .param p1, "stream"    # Ljava/io/InputStream;
    .param p2, "listener"    # Lnet/gotev/uploadservice/http/BodyWriter$OnStreamWriteListener;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 42
    if-eqz p2, :cond_1

    .line 45
    sget v0, Lnet/gotev/uploadservice/UploadService;->BUFFER_SIZE:I

    new-array v0, v0, [B

    .line 48
    .local v0, "buffer":[B
    :goto_0
    invoke-interface {p2}, Lnet/gotev/uploadservice/http/BodyWriter$OnStreamWriteListener;->shouldContinueWriting()Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x0

    array-length v2, v0

    invoke-virtual {p1, v0, v1, v2}, Ljava/io/InputStream;->read([BII)I

    move-result v1

    move v2, v1

    .local v2, "bytesRead":I
    if-lez v1, :cond_0

    .line 49
    invoke-virtual {p0, v0, v2}, Lnet/gotev/uploadservice/http/BodyWriter;->write([BI)V

    .line 50
    invoke-virtual {p0}, Lnet/gotev/uploadservice/http/BodyWriter;->flush()V

    .line 51
    invoke-interface {p2, v2}, Lnet/gotev/uploadservice/http/BodyWriter$OnStreamWriteListener;->onBytesWritten(I)V

    .end local v2    # "bytesRead":I
    goto :goto_0

    .line 53
    :cond_0
    return-void

    .line 43
    .end local v0    # "buffer":[B
    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "listener MUST not be null!"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    goto :goto_2

    :goto_1
    throw v0

    :goto_2
    goto :goto_1
.end method
