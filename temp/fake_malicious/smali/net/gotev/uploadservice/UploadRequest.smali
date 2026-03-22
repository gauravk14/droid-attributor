.class public abstract Lnet/gotev/uploadservice/UploadRequest;
.super Ljava/lang/Object;
.source "UploadRequest.java"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<B:",
        "Lnet/gotev/uploadservice/UploadRequest<",
        "TB;>;>",
        "Ljava/lang/Object;"
    }
.end annotation


# static fields
.field private static final LOG_TAG:Ljava/lang/String;


# instance fields
.field protected final context:Landroid/content/Context;

.field protected delegate:Lnet/gotev/uploadservice/UploadStatusDelegate;

.field protected final params:Lnet/gotev/uploadservice/UploadTaskParameters;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 15
    const-class v0, Lnet/gotev/uploadservice/UploadRequest;

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Lnet/gotev/uploadservice/UploadRequest;->LOG_TAG:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "uploadId"    # Ljava/lang/String;
    .param p3, "serverUrl"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/IllegalArgumentException;
        }
    .end annotation

    .line 32
    .local p0, "this":Lnet/gotev/uploadservice/UploadRequest;, "Lnet/gotev/uploadservice/UploadRequest<TB;>;"
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    new-instance v0, Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-direct {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 34
    if-eqz p1, :cond_3

    .line 37
    if-eqz p3, :cond_2

    const-string v0, ""

    invoke-virtual {v0, p3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    .line 41
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadRequest;->context:Landroid/content/Context;

    .line 43
    if-eqz p2, :cond_1

    invoke-virtual {p2}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 47
    :cond_0
    sget-object v0, Lnet/gotev/uploadservice/UploadRequest;->LOG_TAG:Ljava/lang/String;

    const-string v1, "setting provided upload ID"

    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 48
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0, p2}, Lnet/gotev/uploadservice/UploadTaskParameters;->setId(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadTaskParameters;

    goto :goto_1

    .line 44
    :cond_1
    :goto_0
    sget-object v0, Lnet/gotev/uploadservice/UploadRequest;->LOG_TAG:Ljava/lang/String;

    const-string v1, "null or empty upload ID. Generating it"

    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 45
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->setId(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 51
    :goto_1
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0, p3}, Lnet/gotev/uploadservice/UploadTaskParameters;->setServerUrl(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 52
    sget-object v0, Lnet/gotev/uploadservice/UploadRequest;->LOG_TAG:Ljava/lang/String;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Created new upload request to "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 53
    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getServerUrl()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " with ID: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    .line 52
    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 54
    return-void

    .line 38
    :cond_2
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Server URL cannot be null or empty"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 35
    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Context MUST not be null!"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method protected abstract getTaskClass()Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/lang/Class<",
            "+",
            "Lnet/gotev/uploadservice/UploadTask;",
            ">;"
        }
    .end annotation
.end method

.method protected initializeIntent(Landroid/content/Intent;)V
    .locals 3
    .param p1, "intent"    # Landroid/content/Intent;

    .line 80
    .local p0, "this":Lnet/gotev/uploadservice/UploadRequest;, "Lnet/gotev/uploadservice/UploadRequest<TB;>;"
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    const-string v1, "taskParameters"

    invoke-virtual {p1, v1, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 82
    invoke-virtual {p0}, Lnet/gotev/uploadservice/UploadRequest;->getTaskClass()Ljava/lang/Class;

    move-result-object v0

    .line 83
    .local v0, "taskClass":Ljava/lang/Class;
    if-eqz v0, :cond_0

    .line 86
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    const-string v2, "taskClass"

    invoke-virtual {p1, v2, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 87
    return-void

    .line 84
    :cond_0
    new-instance v1, Ljava/lang/RuntimeException;

    const-string v2, "The request must specify a task class!"

    invoke-direct {v1, v2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v1
.end method

.method protected final self()Lnet/gotev/uploadservice/UploadRequest;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TB;"
        }
    .end annotation

    .line 91
    .local p0, "this":Lnet/gotev/uploadservice/UploadRequest;, "Lnet/gotev/uploadservice/UploadRequest<TB;>;"
    return-object p0
.end method

.method public setAutoDeleteFilesAfterSuccessfulUpload(Z)Lnet/gotev/uploadservice/UploadRequest;
    .locals 1
    .param p1, "autoDeleteFiles"    # Z
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z)TB;"
        }
    .end annotation

    .line 116
    .local p0, "this":Lnet/gotev/uploadservice/UploadRequest;, "Lnet/gotev/uploadservice/UploadRequest<TB;>;"
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0, p1}, Lnet/gotev/uploadservice/UploadTaskParameters;->setAutoDeleteSuccessfullyUploadedFiles(Z)Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 117
    invoke-virtual {p0}, Lnet/gotev/uploadservice/UploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v0

    return-object v0
.end method

.method public setDelegate(Lnet/gotev/uploadservice/UploadStatusDelegate;)Lnet/gotev/uploadservice/UploadRequest;
    .locals 1
    .param p1, "delegate"    # Lnet/gotev/uploadservice/UploadStatusDelegate;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lnet/gotev/uploadservice/UploadStatusDelegate;",
            ")TB;"
        }
    .end annotation

    .line 142
    .local p0, "this":Lnet/gotev/uploadservice/UploadRequest;, "Lnet/gotev/uploadservice/UploadRequest<TB;>;"
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadRequest;->delegate:Lnet/gotev/uploadservice/UploadStatusDelegate;

    .line 143
    invoke-virtual {p0}, Lnet/gotev/uploadservice/UploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v0

    return-object v0
.end method

.method public setMaxRetries(I)Lnet/gotev/uploadservice/UploadRequest;
    .locals 1
    .param p1, "maxRetries"    # I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)TB;"
        }
    .end annotation

    .line 128
    .local p0, "this":Lnet/gotev/uploadservice/UploadRequest;, "Lnet/gotev/uploadservice/UploadRequest<TB;>;"
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0, p1}, Lnet/gotev/uploadservice/UploadTaskParameters;->setMaxRetries(I)Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 129
    invoke-virtual {p0}, Lnet/gotev/uploadservice/UploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v0

    return-object v0
.end method

.method public setNotificationConfig(Lnet/gotev/uploadservice/UploadNotificationConfig;)Lnet/gotev/uploadservice/UploadRequest;
    .locals 1
    .param p1, "config"    # Lnet/gotev/uploadservice/UploadNotificationConfig;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lnet/gotev/uploadservice/UploadNotificationConfig;",
            ")TB;"
        }
    .end annotation

    .line 104
    .local p0, "this":Lnet/gotev/uploadservice/UploadRequest;, "Lnet/gotev/uploadservice/UploadRequest<TB;>;"
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0, p1}, Lnet/gotev/uploadservice/UploadTaskParameters;->setNotificationConfig(Lnet/gotev/uploadservice/UploadNotificationConfig;)Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 105
    invoke-virtual {p0}, Lnet/gotev/uploadservice/UploadRequest;->self()Lnet/gotev/uploadservice/UploadRequest;

    move-result-object v0

    return-object v0
.end method

.method public startUpload()Ljava/lang/String;
    .locals 3

    .line 63
    .local p0, "this":Lnet/gotev/uploadservice/UploadRequest;, "Lnet/gotev/uploadservice/UploadRequest<TB;>;"
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadRequest;->delegate:Lnet/gotev/uploadservice/UploadStatusDelegate;

    invoke-static {v0, v1}, Lnet/gotev/uploadservice/UploadService;->setUploadStatusDelegate(Ljava/lang/String;Lnet/gotev/uploadservice/UploadStatusDelegate;)V

    .line 65
    new-instance v0, Landroid/content/Intent;

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadRequest;->context:Landroid/content/Context;

    const-class v2, Lnet/gotev/uploadservice/UploadService;

    invoke-direct {v0, v1, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 66
    .local v0, "intent":Landroid/content/Intent;
    invoke-virtual {p0, v0}, Lnet/gotev/uploadservice/UploadRequest;->initializeIntent(Landroid/content/Intent;)V

    .line 67
    invoke-static {}, Lnet/gotev/uploadservice/UploadService;->getActionUpload()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 68
    iget-object v1, p0, Lnet/gotev/uploadservice/UploadRequest;->context:Landroid/content/Context;

    invoke-virtual {v1, v0}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    .line 70
    iget-object v1, p0, Lnet/gotev/uploadservice/UploadRequest;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v1

    return-object v1
.end method
