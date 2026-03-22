.class public Lnet/gotev/uploadservice/UploadServiceBroadcastReceiver;
.super Landroid/content/BroadcastReceiver;
.source "UploadServiceBroadcastReceiver.java"

# interfaces
.implements Lnet/gotev/uploadservice/UploadStatusDelegate;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 20
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 53
    return-void
.end method


# virtual methods
.method public onCancelled(Landroid/content/Context;Lnet/gotev/uploadservice/UploadInfo;)V
    .locals 0
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "uploadInfo"    # Lnet/gotev/uploadservice/UploadInfo;

    .line 99
    return-void
.end method

.method public onCompleted(Landroid/content/Context;Lnet/gotev/uploadservice/UploadInfo;Lnet/gotev/uploadservice/ServerResponse;)V
    .locals 0
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "uploadInfo"    # Lnet/gotev/uploadservice/UploadInfo;
    .param p3, "serverResponse"    # Lnet/gotev/uploadservice/ServerResponse;

    .line 95
    return-void
.end method

.method public onError(Landroid/content/Context;Lnet/gotev/uploadservice/UploadInfo;Ljava/lang/Exception;)V
    .locals 0
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "uploadInfo"    # Lnet/gotev/uploadservice/UploadInfo;
    .param p3, "exception"    # Ljava/lang/Exception;

    .line 91
    return-void
.end method

.method public onProgress(Landroid/content/Context;Lnet/gotev/uploadservice/UploadInfo;)V
    .locals 0
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "uploadInfo"    # Lnet/gotev/uploadservice/UploadInfo;

    .line 87
    return-void
.end method

.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 3
    .param p1, "context"    # Landroid/content/Context;
    .param p2, "intent"    # Landroid/content/Intent;

    .line 25
    if-eqz p2, :cond_6

    invoke-static {}, Lnet/gotev/uploadservice/UploadService;->getActionBroadcast()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_1

    .line 28
    :cond_0
    const-string v0, "broadcastData"

    invoke-virtual {p2, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/BroadcastData;

    .line 30
    .local v0, "data":Lnet/gotev/uploadservice/BroadcastData;
    if-nez v0, :cond_1

    .line 31
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    const-string v2, "Missing intent parameter: broadcastData"

    invoke-static {v1, v2}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    return-void

    .line 35
    :cond_1
    sget-object v1, Lnet/gotev/uploadservice/UploadServiceBroadcastReceiver$1;->$SwitchMap$net$gotev$uploadservice$BroadcastData$Status:[I

    invoke-virtual {v0}, Lnet/gotev/uploadservice/BroadcastData;->getStatus()Lnet/gotev/uploadservice/BroadcastData$Status;

    move-result-object v2

    invoke-virtual {v2}, Lnet/gotev/uploadservice/BroadcastData$Status;->ordinal()I

    move-result v2

    aget v1, v1, v2

    const/4 v2, 0x1

    if-eq v1, v2, :cond_5

    const/4 v2, 0x2

    if-eq v1, v2, :cond_4

    const/4 v2, 0x3

    if-eq v1, v2, :cond_3

    const/4 v2, 0x4

    if-eq v1, v2, :cond_2

    goto :goto_0

    .line 49
    :cond_2
    invoke-virtual {v0}, Lnet/gotev/uploadservice/BroadcastData;->getUploadInfo()Lnet/gotev/uploadservice/UploadInfo;

    move-result-object v1

    invoke-virtual {p0, p1, v1}, Lnet/gotev/uploadservice/UploadServiceBroadcastReceiver;->onCancelled(Landroid/content/Context;Lnet/gotev/uploadservice/UploadInfo;)V

    .line 50
    goto :goto_0

    .line 45
    :cond_3
    invoke-virtual {v0}, Lnet/gotev/uploadservice/BroadcastData;->getUploadInfo()Lnet/gotev/uploadservice/UploadInfo;

    move-result-object v1

    invoke-virtual {p0, p1, v1}, Lnet/gotev/uploadservice/UploadServiceBroadcastReceiver;->onProgress(Landroid/content/Context;Lnet/gotev/uploadservice/UploadInfo;)V

    .line 46
    goto :goto_0

    .line 41
    :cond_4
    invoke-virtual {v0}, Lnet/gotev/uploadservice/BroadcastData;->getUploadInfo()Lnet/gotev/uploadservice/UploadInfo;

    move-result-object v1

    invoke-virtual {v0}, Lnet/gotev/uploadservice/BroadcastData;->getServerResponse()Lnet/gotev/uploadservice/ServerResponse;

    move-result-object v2

    invoke-virtual {p0, p1, v1, v2}, Lnet/gotev/uploadservice/UploadServiceBroadcastReceiver;->onCompleted(Landroid/content/Context;Lnet/gotev/uploadservice/UploadInfo;Lnet/gotev/uploadservice/ServerResponse;)V

    .line 42
    goto :goto_0

    .line 37
    :cond_5
    invoke-virtual {v0}, Lnet/gotev/uploadservice/BroadcastData;->getUploadInfo()Lnet/gotev/uploadservice/UploadInfo;

    move-result-object v1

    invoke-virtual {v0}, Lnet/gotev/uploadservice/BroadcastData;->getException()Ljava/lang/Exception;

    move-result-object v2

    invoke-virtual {p0, p1, v1, v2}, Lnet/gotev/uploadservice/UploadServiceBroadcastReceiver;->onError(Landroid/content/Context;Lnet/gotev/uploadservice/UploadInfo;Ljava/lang/Exception;)V

    .line 38
    nop

    .line 55
    :goto_0
    return-void

    .line 26
    .end local v0    # "data":Lnet/gotev/uploadservice/BroadcastData;
    :cond_6
    :goto_1
    return-void
.end method

.method public register(Landroid/content/Context;)V
    .locals 2
    .param p1, "context"    # Landroid/content/Context;

    .line 67
    new-instance v0, Landroid/content/IntentFilter;

    invoke-direct {v0}, Landroid/content/IntentFilter;-><init>()V

    .line 68
    .local v0, "intentFilter":Landroid/content/IntentFilter;
    invoke-static {}, Lnet/gotev/uploadservice/UploadService;->getActionBroadcast()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 69
    invoke-virtual {p1, p0, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 70
    return-void
.end method

.method public unregister(Landroid/content/Context;)V
    .locals 0
    .param p1, "context"    # Landroid/content/Context;

    .line 82
    invoke-virtual {p1, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 83
    return-void
.end method
