.class public abstract Lnet/gotev/uploadservice/UploadTask;
.super Ljava/lang/Object;
.source "UploadTask.java"

# interfaces
.implements Ljava/lang/Runnable;


# static fields
.field protected static final EMPTY_RESPONSE:[B

.field private static final LOG_TAG:Ljava/lang/String;

.field protected static final TASK_COMPLETED_SUCCESSFULLY:I = 0xc8


# instance fields
.field private attempts:I

.field private lastProgressNotificationTime:J

.field private mainThreadHandler:Landroid/os/Handler;

.field private notification:Landroidx/core/app/NotificationCompat$Builder;

.field private notificationId:I

.field private notificationManager:Landroid/app/NotificationManager;

.field protected params:Lnet/gotev/uploadservice/UploadTaskParameters;

.field protected service:Lnet/gotev/uploadservice/UploadService;

.field protected shouldContinue:Z

.field private final startTime:J

.field private final successfullyUploadedFiles:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field protected totalBytes:J

.field protected uploadedBytes:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 25
    const-class v0, Lnet/gotev/uploadservice/UploadTask;

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Lnet/gotev/uploadservice/UploadTask;->LOG_TAG:Ljava/lang/String;

    .line 35
    const-string v0, "UTF-8"

    invoke-static {v0}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    move-result-object v0

    const-string v1, ""

    invoke-virtual {v1, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v0

    sput-object v0, Lnet/gotev/uploadservice/UploadTask;->EMPTY_RESPONSE:[B

    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 103
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 45
    const/4 v0, 0x0

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 50
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->successfullyUploadedFiles:Ljava/util/List;

    .line 61
    const/4 v0, 0x1

    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadTask;->shouldContinue:Z

    .line 104
    new-instance v0, Ljava/util/Date;

    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    invoke-virtual {v0}, Ljava/util/Date;->getTime()J

    move-result-wide v0

    iput-wide v0, p0, Lnet/gotev/uploadservice/UploadTask;->startTime:J

    .line 105
    return-void
.end method

.method private broadcastError(Ljava/lang/Exception;)V
    .locals 19
    .param p1, "exception"    # Ljava/lang/Exception;

    .line 377
    move-object/from16 v6, p0

    move-object/from16 v7, p1

    sget-object v0, Lnet/gotev/uploadservice/UploadTask;->LOG_TAG:Ljava/lang/String;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Broadcasting error for upload with ID: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 378
    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, ". "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual/range {p1 .. p1}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    .line 377
    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->info(Ljava/lang/String;Ljava/lang/String;)V

    .line 380
    new-instance v0, Lnet/gotev/uploadservice/UploadInfo;

    iget-object v1, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v9

    iget-wide v10, v6, Lnet/gotev/uploadservice/UploadTask;->startTime:J

    iget-wide v12, v6, Lnet/gotev/uploadservice/UploadTask;->uploadedBytes:J

    iget-wide v14, v6, Lnet/gotev/uploadservice/UploadTask;->totalBytes:J

    iget v1, v6, Lnet/gotev/uploadservice/UploadTask;->attempts:I

    add-int/lit8 v16, v1, -0x1

    iget-object v1, v6, Lnet/gotev/uploadservice/UploadTask;->successfullyUploadedFiles:Ljava/util/List;

    iget-object v2, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 383
    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v18

    move-object v8, v0

    move-object/from16 v17, v1

    invoke-direct/range {v8 .. v18}, Lnet/gotev/uploadservice/UploadInfo;-><init>(Ljava/lang/String;JJJILjava/util/List;I)V

    .line 385
    .local v8, "uploadInfo":Lnet/gotev/uploadservice/UploadInfo;
    new-instance v0, Lnet/gotev/uploadservice/BroadcastData;

    invoke-direct {v0}, Lnet/gotev/uploadservice/BroadcastData;-><init>()V

    sget-object v1, Lnet/gotev/uploadservice/BroadcastData$Status;->ERROR:Lnet/gotev/uploadservice/BroadcastData$Status;

    .line 386
    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/BroadcastData;->setStatus(Lnet/gotev/uploadservice/BroadcastData$Status;)Lnet/gotev/uploadservice/BroadcastData;

    move-result-object v0

    .line 387
    invoke-virtual {v0, v8}, Lnet/gotev/uploadservice/BroadcastData;->setUploadInfo(Lnet/gotev/uploadservice/UploadInfo;)Lnet/gotev/uploadservice/BroadcastData;

    move-result-object v0

    .line 388
    invoke-virtual {v0, v7}, Lnet/gotev/uploadservice/BroadcastData;->setException(Ljava/lang/Exception;)Lnet/gotev/uploadservice/BroadcastData;

    move-result-object v9

    .line 390
    .local v9, "data":Lnet/gotev/uploadservice/BroadcastData;
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Lnet/gotev/uploadservice/UploadService;->getUploadStatusDelegate(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadStatusDelegate;

    move-result-object v10

    .line 391
    .local v10, "delegate":Lnet/gotev/uploadservice/UploadStatusDelegate;
    if-eqz v10, :cond_0

    .line 392
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->mainThreadHandler:Landroid/os/Handler;

    new-instance v1, Lnet/gotev/uploadservice/UploadTask$4;

    invoke-direct {v1, v6, v10, v8, v7}, Lnet/gotev/uploadservice/UploadTask$4;-><init>(Lnet/gotev/uploadservice/UploadTask;Lnet/gotev/uploadservice/UploadStatusDelegate;Lnet/gotev/uploadservice/UploadInfo;Ljava/lang/Exception;)V

    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    goto :goto_0

    .line 399
    :cond_0
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {v9}, Lnet/gotev/uploadservice/BroadcastData;->getIntent()Landroid/content/Intent;

    move-result-object v1

    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/UploadService;->sendBroadcast(Landroid/content/Intent;)V

    .line 402
    :goto_0
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v11

    .line 404
    .local v11, "notificationConfig":Lnet/gotev/uploadservice/UploadNotificationConfig;
    if-eqz v11, :cond_1

    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getErrorMessage()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 405
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getErrorMessage()Ljava/lang/String;

    move-result-object v2

    .line 406
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->isAutoClearOnError()Z

    move-result v3

    .line 407
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getErrorIconResourceID()I

    move-result v4

    .line 408
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getErrorIconColorResourceID()I

    move-result v5

    .line 405
    move-object/from16 v0, p0

    move-object v1, v8

    invoke-direct/range {v0 .. v5}, Lnet/gotev/uploadservice/UploadTask;->updateNotification(Lnet/gotev/uploadservice/UploadInfo;Ljava/lang/String;ZII)V

    .line 411
    :cond_1
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    iget-object v1, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/UploadService;->taskCompleted(Ljava/lang/String;)V

    .line 412
    return-void
.end method

.method private createNotification(Lnet/gotev/uploadservice/UploadInfo;)V
    .locals 4
    .param p1, "uploadInfo"    # Lnet/gotev/uploadservice/UploadInfo;

    .line 420
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v0

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getInProgressMessage()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    goto/16 :goto_1

    .line 422
    :cond_0
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->notification:Landroidx/core/app/NotificationCompat$Builder;

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getTitle()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, p1}, Lnet/gotev/uploadservice/Placeholders;->replace(Ljava/lang/String;Lnet/gotev/uploadservice/UploadInfo;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setContentTitle(Ljava/lang/CharSequence;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 423
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getInProgressMessage()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, p1}, Lnet/gotev/uploadservice/Placeholders;->replace(Ljava/lang/String;Lnet/gotev/uploadservice/UploadInfo;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setContentText(Ljava/lang/CharSequence;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 424
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    iget-object v2, p0, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {v1, v2}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getPendingIntent(Landroid/content/Context;)Landroid/app/PendingIntent;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setContentIntent(Landroid/app/PendingIntent;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 425
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getIconResourceID()I

    move-result v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setSmallIcon(I)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 426
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getIconColorResourceID()I

    move-result v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setColor(I)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    sget-object v1, Lnet/gotev/uploadservice/UploadService;->NAMESPACE:Ljava/lang/String;

    .line 427
    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setGroup(Ljava/lang/String;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    const/16 v1, 0x64

    const/4 v2, 0x0

    .line 428
    const/4 v3, 0x1

    invoke-virtual {v0, v1, v2, v3}, Landroidx/core/app/NotificationCompat$Builder;->setProgress(IIZ)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    .line 429
    invoke-virtual {v0, v3}, Landroidx/core/app/NotificationCompat$Builder;->setOngoing(Z)Landroidx/core/app/NotificationCompat$Builder;

    .line 431
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->notification:Landroidx/core/app/NotificationCompat$Builder;

    invoke-virtual {v0}, Landroidx/core/app/NotificationCompat$Builder;->build()Landroid/app/Notification;

    move-result-object v0

    .line 433
    .local v0, "builtNotification":Landroid/app/Notification;
    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    iget-object v2, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2, v0}, Lnet/gotev/uploadservice/UploadService;->holdForegroundNotification(Ljava/lang/String;Landroid/app/Notification;)Z

    move-result v1

    if-eqz v1, :cond_1

    .line 434
    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->notificationManager:Landroid/app/NotificationManager;

    iget v2, p0, Lnet/gotev/uploadservice/UploadTask;->notificationId:I

    invoke-virtual {v1, v2}, Landroid/app/NotificationManager;->cancel(I)V

    goto :goto_0

    .line 436
    :cond_1
    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->notificationManager:Landroid/app/NotificationManager;

    iget v2, p0, Lnet/gotev/uploadservice/UploadTask;->notificationId:I

    invoke-virtual {v1, v2, v0}, Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V

    .line 438
    :goto_0
    return-void

    .line 420
    .end local v0    # "builtNotification":Landroid/app/Notification;
    :cond_2
    :goto_1
    return-void
.end method

.method private deleteFile(Ljava/io/File;)Z
    .locals 5
    .param p1, "fileToDelete"    # Ljava/io/File;

    .line 511
    const/4 v0, 0x0

    .line 514
    .local v0, "deleted":Z
    :try_start_0
    invoke-virtual {p1}, Ljava/io/File;->delete()Z

    move-result v1

    move v0, v1

    .line 516
    if-nez v0, :cond_0

    .line 517
    sget-object v1, Lnet/gotev/uploadservice/UploadTask;->LOG_TAG:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Unable to delete: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 518
    invoke-virtual {p1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    .line 517
    invoke-static {v1, v2}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_0

    .line 520
    :cond_0
    sget-object v1, Lnet/gotev/uploadservice/UploadTask;->LOG_TAG:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Successfully deleted: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 521
    invoke-virtual {p1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    .line 520
    invoke-static {v1, v2}, Lnet/gotev/uploadservice/Logger;->info(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 528
    :goto_0
    goto :goto_1

    .line 524
    :catch_0
    move-exception v1

    .line 525
    .local v1, "exc":Ljava/lang/Exception;
    sget-object v2, Lnet/gotev/uploadservice/UploadTask;->LOG_TAG:Ljava/lang/String;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Error while deleting: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 526
    invoke-virtual {p1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, " Check if you granted: android.permission.WRITE_EXTERNAL_STORAGE"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    .line 525
    invoke-static {v2, v3, v1}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 530
    .end local v1    # "exc":Ljava/lang/Exception;
    :goto_1
    return v0
.end method

.method private setRingtone()V
    .locals 3

    .line 468
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v0

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadNotificationConfig;->isRingToneEnabled()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 469
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->notification:Landroidx/core/app/NotificationCompat$Builder;

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    const/4 v2, 0x2

    invoke-static {v1, v2}, Landroid/media/RingtoneManager;->getActualDefaultRingtoneUri(Landroid/content/Context;I)Landroid/net/Uri;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setSound(Landroid/net/Uri;)Landroidx/core/app/NotificationCompat$Builder;

    .line 470
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->notification:Landroidx/core/app/NotificationCompat$Builder;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setOnlyAlertOnce(Z)Landroidx/core/app/NotificationCompat$Builder;

    .line 473
    :cond_0
    return-void
.end method

.method private updateNotification(Lnet/gotev/uploadservice/UploadInfo;Ljava/lang/String;ZII)V
    .locals 3
    .param p1, "uploadInfo"    # Lnet/gotev/uploadservice/UploadInfo;
    .param p2, "message"    # Ljava/lang/String;
    .param p3, "autoClearOnSuccess"    # Z
    .param p4, "iconResourceID"    # I
    .param p5, "iconColorResourceID"    # I

    .line 479
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v0

    if-nez v0, :cond_0

    return-void

    .line 481
    :cond_0
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->notificationManager:Landroid/app/NotificationManager;

    iget v1, p0, Lnet/gotev/uploadservice/UploadTask;->notificationId:I

    invoke-virtual {v0, v1}, Landroid/app/NotificationManager;->cancel(I)V

    .line 483
    if-nez p2, :cond_1

    return-void

    .line 485
    :cond_1
    if-nez p3, :cond_2

    .line 486
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->notification:Landroidx/core/app/NotificationCompat$Builder;

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getTitle()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, p1}, Lnet/gotev/uploadservice/Placeholders;->replace(Ljava/lang/String;Lnet/gotev/uploadservice/UploadInfo;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setContentTitle(Ljava/lang/CharSequence;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    .line 487
    invoke-static {p2, p1}, Lnet/gotev/uploadservice/Placeholders;->replace(Ljava/lang/String;Lnet/gotev/uploadservice/UploadInfo;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setContentText(Ljava/lang/CharSequence;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 488
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    iget-object v2, p0, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {v1, v2}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getPendingIntent(Landroid/content/Context;)Landroid/app/PendingIntent;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setContentIntent(Landroid/app/PendingIntent;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 489
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadNotificationConfig;->isClearOnAction()Z

    move-result v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setAutoCancel(Z)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    .line 490
    invoke-virtual {v0, p4}, Landroidx/core/app/NotificationCompat$Builder;->setSmallIcon(I)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    .line 491
    invoke-virtual {v0, p5}, Landroidx/core/app/NotificationCompat$Builder;->setColor(I)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    sget-object v1, Lnet/gotev/uploadservice/UploadService;->NAMESPACE:Ljava/lang/String;

    .line 492
    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setGroup(Ljava/lang/String;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    .line 493
    const/4 v1, 0x0

    invoke-virtual {v0, v1, v1, v1}, Landroidx/core/app/NotificationCompat$Builder;->setProgress(IIZ)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    .line 494
    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setOngoing(Z)Landroidx/core/app/NotificationCompat$Builder;

    .line 495
    invoke-direct {p0}, Lnet/gotev/uploadservice/UploadTask;->setRingtone()V

    .line 499
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->notificationManager:Landroid/app/NotificationManager;

    iget v1, p0, Lnet/gotev/uploadservice/UploadTask;->notificationId:I

    add-int/lit8 v1, v1, 0x1

    iget-object v2, p0, Lnet/gotev/uploadservice/UploadTask;->notification:Landroidx/core/app/NotificationCompat$Builder;

    invoke-virtual {v2}, Landroidx/core/app/NotificationCompat$Builder;->build()Landroid/app/Notification;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V

    .line 501
    :cond_2
    return-void
.end method

.method private updateNotificationProgress(Lnet/gotev/uploadservice/UploadInfo;)V
    .locals 5
    .param p1, "uploadInfo"    # Lnet/gotev/uploadservice/UploadInfo;

    .line 446
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v0

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getInProgressMessage()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    goto/16 :goto_1

    .line 448
    :cond_0
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->notification:Landroidx/core/app/NotificationCompat$Builder;

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getTitle()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, p1}, Lnet/gotev/uploadservice/Placeholders;->replace(Ljava/lang/String;Lnet/gotev/uploadservice/UploadInfo;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setContentTitle(Ljava/lang/CharSequence;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 449
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getInProgressMessage()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, p1}, Lnet/gotev/uploadservice/Placeholders;->replace(Ljava/lang/String;Lnet/gotev/uploadservice/UploadInfo;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setContentText(Ljava/lang/CharSequence;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 450
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    iget-object v2, p0, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {v1, v2}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getPendingIntent(Landroid/content/Context;)Landroid/app/PendingIntent;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setContentIntent(Landroid/app/PendingIntent;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 451
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getIconResourceID()I

    move-result v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setSmallIcon(I)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 452
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v1

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getIconColorResourceID()I

    move-result v1

    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setColor(I)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    sget-object v1, Lnet/gotev/uploadservice/UploadService;->NAMESPACE:Ljava/lang/String;

    .line 453
    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setGroup(Ljava/lang/String;)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    .line 454
    invoke-virtual {p1}, Lnet/gotev/uploadservice/UploadInfo;->getTotalBytes()J

    move-result-wide v1

    long-to-int v2, v1

    invoke-virtual {p1}, Lnet/gotev/uploadservice/UploadInfo;->getUploadedBytes()J

    move-result-wide v3

    long-to-int v1, v3

    const/4 v3, 0x0

    invoke-virtual {v0, v2, v1, v3}, Landroidx/core/app/NotificationCompat$Builder;->setProgress(IIZ)Landroidx/core/app/NotificationCompat$Builder;

    move-result-object v0

    const/4 v1, 0x1

    .line 455
    invoke-virtual {v0, v1}, Landroidx/core/app/NotificationCompat$Builder;->setOngoing(Z)Landroidx/core/app/NotificationCompat$Builder;

    .line 457
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->notification:Landroidx/core/app/NotificationCompat$Builder;

    invoke-virtual {v0}, Landroidx/core/app/NotificationCompat$Builder;->build()Landroid/app/Notification;

    move-result-object v0

    .line 459
    .local v0, "builtNotification":Landroid/app/Notification;
    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    iget-object v2, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2, v0}, Lnet/gotev/uploadservice/UploadService;->holdForegroundNotification(Ljava/lang/String;Landroid/app/Notification;)Z

    move-result v1

    if-eqz v1, :cond_1

    .line 460
    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->notificationManager:Landroid/app/NotificationManager;

    iget v2, p0, Lnet/gotev/uploadservice/UploadTask;->notificationId:I

    invoke-virtual {v1, v2}, Landroid/app/NotificationManager;->cancel(I)V

    goto :goto_0

    .line 462
    :cond_1
    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->notificationManager:Landroid/app/NotificationManager;

    iget v2, p0, Lnet/gotev/uploadservice/UploadTask;->notificationId:I

    invoke-virtual {v1, v2, v0}, Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V

    .line 464
    :goto_0
    return-void

    .line 446
    .end local v0    # "builtNotification":Landroid/app/Notification;
    :cond_2
    :goto_1
    return-void
.end method


# virtual methods
.method protected final addSuccessfullyUploadedFile(Ljava/lang/String;)V
    .locals 1
    .param p1, "absolutePath"    # Ljava/lang/String;

    .line 350
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->successfullyUploadedFiles:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    .line 351
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->successfullyUploadedFiles:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 353
    :cond_0
    return-void
.end method

.method protected final broadcastCancelled()V
    .locals 18

    .line 310
    move-object/from16 v6, p0

    sget-object v0, Lnet/gotev/uploadservice/UploadTask;->LOG_TAG:Ljava/lang/String;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Broadcasting cancellation for upload with ID: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 312
    new-instance v0, Lnet/gotev/uploadservice/UploadInfo;

    iget-object v1, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v8

    iget-wide v9, v6, Lnet/gotev/uploadservice/UploadTask;->startTime:J

    iget-wide v11, v6, Lnet/gotev/uploadservice/UploadTask;->uploadedBytes:J

    iget-wide v13, v6, Lnet/gotev/uploadservice/UploadTask;->totalBytes:J

    iget v1, v6, Lnet/gotev/uploadservice/UploadTask;->attempts:I

    add-int/lit8 v15, v1, -0x1

    iget-object v1, v6, Lnet/gotev/uploadservice/UploadTask;->successfullyUploadedFiles:Ljava/util/List;

    iget-object v2, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 315
    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v17

    move-object v7, v0

    move-object/from16 v16, v1

    invoke-direct/range {v7 .. v17}, Lnet/gotev/uploadservice/UploadInfo;-><init>(Ljava/lang/String;JJJILjava/util/List;I)V

    .line 317
    .local v7, "uploadInfo":Lnet/gotev/uploadservice/UploadInfo;
    new-instance v0, Lnet/gotev/uploadservice/BroadcastData;

    invoke-direct {v0}, Lnet/gotev/uploadservice/BroadcastData;-><init>()V

    sget-object v1, Lnet/gotev/uploadservice/BroadcastData$Status;->CANCELLED:Lnet/gotev/uploadservice/BroadcastData$Status;

    .line 318
    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/BroadcastData;->setStatus(Lnet/gotev/uploadservice/BroadcastData$Status;)Lnet/gotev/uploadservice/BroadcastData;

    move-result-object v0

    .line 319
    invoke-virtual {v0, v7}, Lnet/gotev/uploadservice/BroadcastData;->setUploadInfo(Lnet/gotev/uploadservice/UploadInfo;)Lnet/gotev/uploadservice/BroadcastData;

    move-result-object v8

    .line 321
    .local v8, "data":Lnet/gotev/uploadservice/BroadcastData;
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Lnet/gotev/uploadservice/UploadService;->getUploadStatusDelegate(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadStatusDelegate;

    move-result-object v9

    .line 322
    .local v9, "delegate":Lnet/gotev/uploadservice/UploadStatusDelegate;
    if-eqz v9, :cond_0

    .line 323
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->mainThreadHandler:Landroid/os/Handler;

    new-instance v1, Lnet/gotev/uploadservice/UploadTask$3;

    invoke-direct {v1, v6, v9, v7}, Lnet/gotev/uploadservice/UploadTask$3;-><init>(Lnet/gotev/uploadservice/UploadTask;Lnet/gotev/uploadservice/UploadStatusDelegate;Lnet/gotev/uploadservice/UploadInfo;)V

    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    goto :goto_0

    .line 330
    :cond_0
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {v8}, Lnet/gotev/uploadservice/BroadcastData;->getIntent()Landroid/content/Intent;

    move-result-object v1

    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/UploadService;->sendBroadcast(Landroid/content/Intent;)V

    .line 333
    :goto_0
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v10

    .line 335
    .local v10, "notificationConfig":Lnet/gotev/uploadservice/UploadNotificationConfig;
    if-eqz v10, :cond_1

    .line 336
    invoke-virtual {v10}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getCancelledMessage()Ljava/lang/String;

    move-result-object v2

    .line 337
    invoke-virtual {v10}, Lnet/gotev/uploadservice/UploadNotificationConfig;->isAutoClearOnCancel()Z

    move-result v3

    .line 338
    invoke-virtual {v10}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getCancelledIconResourceID()I

    move-result v4

    .line 339
    invoke-virtual {v10}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getCancelledIconColorResourceID()I

    move-result v5

    .line 336
    move-object/from16 v0, p0

    move-object v1, v7

    invoke-direct/range {v0 .. v5}, Lnet/gotev/uploadservice/UploadTask;->updateNotification(Lnet/gotev/uploadservice/UploadInfo;Ljava/lang/String;ZII)V

    .line 342
    :cond_1
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    iget-object v1, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/UploadService;->taskCompleted(Ljava/lang/String;)V

    .line 343
    return-void
.end method

.method protected final broadcastCompleted(Lnet/gotev/uploadservice/ServerResponse;)V
    .locals 20
    .param p1, "response"    # Lnet/gotev/uploadservice/ServerResponse;

    .line 246
    move-object/from16 v6, p0

    move-object/from16 v7, p1

    invoke-virtual/range {p1 .. p1}, Lnet/gotev/uploadservice/ServerResponse;->getHttpCode()I

    move-result v0

    div-int/lit8 v0, v0, 0x64

    const/4 v1, 0x1

    const/4 v2, 0x2

    if-ne v0, v2, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    move v8, v0

    .line 248
    .local v8, "successfulUpload":Z
    if-eqz v8, :cond_1

    .line 249
    invoke-virtual/range {p0 .. p0}, Lnet/gotev/uploadservice/UploadTask;->onSuccessfulUpload()V

    .line 251
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->isAutoDeleteSuccessfullyUploadedFiles()Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->successfullyUploadedFiles:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1

    .line 252
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->successfullyUploadedFiles:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    .line 253
    .local v2, "filePath":Ljava/lang/String;
    new-instance v3, Ljava/io/File;

    invoke-direct {v3, v2}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    invoke-direct {v6, v3}, Lnet/gotev/uploadservice/UploadTask;->deleteFile(Ljava/io/File;)Z

    .line 254
    .end local v2    # "filePath":Ljava/lang/String;
    goto :goto_1

    .line 258
    :cond_1
    sget-object v0, Lnet/gotev/uploadservice/UploadTask;->LOG_TAG:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Broadcasting upload completed for "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v3, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v3}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v0, v2}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 260
    new-instance v0, Lnet/gotev/uploadservice/UploadInfo;

    iget-object v2, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v10

    iget-wide v11, v6, Lnet/gotev/uploadservice/UploadTask;->startTime:J

    iget-wide v13, v6, Lnet/gotev/uploadservice/UploadTask;->uploadedBytes:J

    iget-wide v2, v6, Lnet/gotev/uploadservice/UploadTask;->totalBytes:J

    iget v4, v6, Lnet/gotev/uploadservice/UploadTask;->attempts:I

    add-int/lit8 v17, v4, -0x1

    iget-object v1, v6, Lnet/gotev/uploadservice/UploadTask;->successfullyUploadedFiles:Ljava/util/List;

    iget-object v4, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 263
    invoke-virtual {v4}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v4

    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v19

    move-object v9, v0

    move-wide v15, v2

    move-object/from16 v18, v1

    invoke-direct/range {v9 .. v19}, Lnet/gotev/uploadservice/UploadInfo;-><init>(Ljava/lang/String;JJJILjava/util/List;I)V

    .line 265
    .local v9, "uploadInfo":Lnet/gotev/uploadservice/UploadInfo;
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Lnet/gotev/uploadservice/UploadService;->getUploadStatusDelegate(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadStatusDelegate;

    move-result-object v10

    .line 266
    .local v10, "delegate":Lnet/gotev/uploadservice/UploadStatusDelegate;
    if-eqz v10, :cond_2

    .line 267
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->mainThreadHandler:Landroid/os/Handler;

    new-instance v1, Lnet/gotev/uploadservice/UploadTask$2;

    invoke-direct {v1, v6, v10, v9, v7}, Lnet/gotev/uploadservice/UploadTask$2;-><init>(Lnet/gotev/uploadservice/UploadTask;Lnet/gotev/uploadservice/UploadStatusDelegate;Lnet/gotev/uploadservice/UploadInfo;Lnet/gotev/uploadservice/ServerResponse;)V

    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    goto :goto_2

    .line 274
    :cond_2
    new-instance v0, Lnet/gotev/uploadservice/BroadcastData;

    invoke-direct {v0}, Lnet/gotev/uploadservice/BroadcastData;-><init>()V

    sget-object v1, Lnet/gotev/uploadservice/BroadcastData$Status;->COMPLETED:Lnet/gotev/uploadservice/BroadcastData$Status;

    .line 275
    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/BroadcastData;->setStatus(Lnet/gotev/uploadservice/BroadcastData$Status;)Lnet/gotev/uploadservice/BroadcastData;

    move-result-object v0

    .line 276
    invoke-virtual {v0, v9}, Lnet/gotev/uploadservice/BroadcastData;->setUploadInfo(Lnet/gotev/uploadservice/UploadInfo;)Lnet/gotev/uploadservice/BroadcastData;

    move-result-object v0

    .line 277
    invoke-virtual {v0, v7}, Lnet/gotev/uploadservice/BroadcastData;->setServerResponse(Lnet/gotev/uploadservice/ServerResponse;)Lnet/gotev/uploadservice/BroadcastData;

    move-result-object v0

    .line 279
    .local v0, "data":Lnet/gotev/uploadservice/BroadcastData;
    iget-object v1, v6, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/BroadcastData;->getIntent()Landroid/content/Intent;

    move-result-object v2

    invoke-virtual {v1, v2}, Lnet/gotev/uploadservice/UploadService;->sendBroadcast(Landroid/content/Intent;)V

    .line 282
    .end local v0    # "data":Lnet/gotev/uploadservice/BroadcastData;
    :goto_2
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v0}, Lnet/gotev/uploadservice/UploadTaskParameters;->getNotificationConfig()Lnet/gotev/uploadservice/UploadNotificationConfig;

    move-result-object v11

    .line 284
    .local v11, "notificationConfig":Lnet/gotev/uploadservice/UploadNotificationConfig;
    if-eqz v11, :cond_4

    .line 285
    if-eqz v8, :cond_3

    .line 286
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getCompletedMessage()Ljava/lang/String;

    move-result-object v2

    .line 287
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->isAutoClearOnSuccess()Z

    move-result v3

    .line 288
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getCompletedIconResourceID()I

    move-result v4

    .line 289
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getCompletedIconColorResourceID()I

    move-result v5

    .line 286
    move-object/from16 v0, p0

    move-object v1, v9

    invoke-direct/range {v0 .. v5}, Lnet/gotev/uploadservice/UploadTask;->updateNotification(Lnet/gotev/uploadservice/UploadInfo;Ljava/lang/String;ZII)V

    goto :goto_3

    .line 291
    :cond_3
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getErrorMessage()Ljava/lang/String;

    move-result-object v2

    .line 292
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->isAutoClearOnError()Z

    move-result v3

    .line 293
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getErrorIconResourceID()I

    move-result v4

    .line 294
    invoke-virtual {v11}, Lnet/gotev/uploadservice/UploadNotificationConfig;->getErrorIconColorResourceID()I

    move-result v5

    .line 291
    move-object/from16 v0, p0

    move-object v1, v9

    invoke-direct/range {v0 .. v5}, Lnet/gotev/uploadservice/UploadTask;->updateNotification(Lnet/gotev/uploadservice/UploadInfo;Ljava/lang/String;ZII)V

    .line 298
    :cond_4
    :goto_3
    iget-object v0, v6, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    iget-object v1, v6, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/UploadService;->taskCompleted(Ljava/lang/String;)V

    .line 299
    return-void
.end method

.method protected final broadcastProgress(JJ)V
    .locals 17
    .param p1, "uploadedBytes"    # J
    .param p3, "totalBytes"    # J

    .line 202
    move-object/from16 v0, p0

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v1

    .line 203
    .local v1, "currentTime":J
    iget-wide v3, v0, Lnet/gotev/uploadservice/UploadTask;->lastProgressNotificationTime:J

    const-wide/16 v5, 0xa6

    add-long/2addr v3, v5

    cmp-long v5, v1, v3

    if-gez v5, :cond_0

    .line 204
    return-void

    .line 207
    :cond_0
    invoke-virtual {v0, v1, v2}, Lnet/gotev/uploadservice/UploadTask;->setLastProgressNotificationTime(J)Lnet/gotev/uploadservice/UploadTask;

    .line 209
    sget-object v3, Lnet/gotev/uploadservice/UploadTask;->LOG_TAG:Ljava/lang/String;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "Broadcasting upload progress for "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v5, v0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v5}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, ": "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-wide/from16 v14, p1

    invoke-virtual {v4, v14, v15}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v5, " bytes of "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-wide/from16 v12, p3

    invoke-virtual {v4, v12, v13}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v3, v4}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 212
    new-instance v3, Lnet/gotev/uploadservice/UploadInfo;

    iget-object v4, v0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v4}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v7

    iget-wide v8, v0, Lnet/gotev/uploadservice/UploadTask;->startTime:J

    iget v4, v0, Lnet/gotev/uploadservice/UploadTask;->attempts:I

    add-int/lit8 v4, v4, -0x1

    iget-object v5, v0, Lnet/gotev/uploadservice/UploadTask;->successfullyUploadedFiles:Ljava/util/List;

    iget-object v6, v0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 215
    invoke-virtual {v6}, Lnet/gotev/uploadservice/UploadTaskParameters;->getFiles()Ljava/util/List;

    move-result-object v6

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v6

    iget-object v10, v0, Lnet/gotev/uploadservice/UploadTask;->successfullyUploadedFiles:Ljava/util/List;

    invoke-interface {v10}, Ljava/util/List;->size()I

    move-result v10

    add-int v16, v6, v10

    move-object v6, v3

    move-wide/from16 v10, p1

    move v14, v4

    move-object v15, v5

    invoke-direct/range {v6 .. v16}, Lnet/gotev/uploadservice/UploadInfo;-><init>(Ljava/lang/String;JJJILjava/util/List;I)V

    .line 217
    .local v3, "uploadInfo":Lnet/gotev/uploadservice/UploadInfo;
    new-instance v4, Lnet/gotev/uploadservice/BroadcastData;

    invoke-direct {v4}, Lnet/gotev/uploadservice/BroadcastData;-><init>()V

    sget-object v5, Lnet/gotev/uploadservice/BroadcastData$Status;->IN_PROGRESS:Lnet/gotev/uploadservice/BroadcastData$Status;

    .line 218
    invoke-virtual {v4, v5}, Lnet/gotev/uploadservice/BroadcastData;->setStatus(Lnet/gotev/uploadservice/BroadcastData$Status;)Lnet/gotev/uploadservice/BroadcastData;

    move-result-object v4

    .line 219
    invoke-virtual {v4, v3}, Lnet/gotev/uploadservice/BroadcastData;->setUploadInfo(Lnet/gotev/uploadservice/UploadInfo;)Lnet/gotev/uploadservice/BroadcastData;

    move-result-object v4

    .line 221
    .local v4, "data":Lnet/gotev/uploadservice/BroadcastData;
    iget-object v5, v0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v5}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v5

    invoke-static {v5}, Lnet/gotev/uploadservice/UploadService;->getUploadStatusDelegate(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadStatusDelegate;

    move-result-object v5

    .line 222
    .local v5, "delegate":Lnet/gotev/uploadservice/UploadStatusDelegate;
    if-eqz v5, :cond_1

    .line 223
    iget-object v6, v0, Lnet/gotev/uploadservice/UploadTask;->mainThreadHandler:Landroid/os/Handler;

    new-instance v7, Lnet/gotev/uploadservice/UploadTask$1;

    invoke-direct {v7, v0, v5, v3}, Lnet/gotev/uploadservice/UploadTask$1;-><init>(Lnet/gotev/uploadservice/UploadTask;Lnet/gotev/uploadservice/UploadStatusDelegate;Lnet/gotev/uploadservice/UploadInfo;)V

    invoke-virtual {v6, v7}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    goto :goto_0

    .line 230
    :cond_1
    iget-object v6, v0, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {v4}, Lnet/gotev/uploadservice/BroadcastData;->getIntent()Landroid/content/Intent;

    move-result-object v7

    invoke-virtual {v6, v7}, Lnet/gotev/uploadservice/UploadService;->sendBroadcast(Landroid/content/Intent;)V

    .line 233
    :goto_0
    invoke-direct {v0, v3}, Lnet/gotev/uploadservice/UploadTask;->updateNotificationProgress(Lnet/gotev/uploadservice/UploadInfo;)V

    .line 234
    return-void
.end method

.method public final cancel()V
    .locals 1

    .line 534
    const/4 v0, 0x0

    iput-boolean v0, p0, Lnet/gotev/uploadservice/UploadTask;->shouldContinue:Z

    .line 535
    return-void
.end method

.method protected final getSuccessfullyUploadedFiles()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 363
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->successfullyUploadedFiles:Ljava/util/List;

    return-object v0
.end method

.method protected init(Lnet/gotev/uploadservice/UploadService;Landroid/content/Intent;)V
    .locals 2
    .param p1, "service"    # Lnet/gotev/uploadservice/UploadService;
    .param p2, "intent"    # Landroid/content/Intent;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .line 117
    const-string v0, "notification"

    invoke-virtual {p1, v0}, Lnet/gotev/uploadservice/UploadService;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/NotificationManager;

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->notificationManager:Landroid/app/NotificationManager;

    .line 118
    new-instance v0, Landroidx/core/app/NotificationCompat$Builder;

    invoke-direct {v0, p1}, Landroidx/core/app/NotificationCompat$Builder;-><init>(Landroid/content/Context;)V

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->notification:Landroidx/core/app/NotificationCompat$Builder;

    .line 119
    iput-object p1, p0, Lnet/gotev/uploadservice/UploadTask;->service:Lnet/gotev/uploadservice/UploadService;

    .line 120
    new-instance v0, Landroid/os/Handler;

    invoke-virtual {p1}, Lnet/gotev/uploadservice/UploadService;->getMainLooper()Landroid/os/Looper;

    move-result-object v1

    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->mainThreadHandler:Landroid/os/Handler;

    .line 121
    const-string v0, "taskParameters"

    invoke-virtual {p2, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/UploadTaskParameters;

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    .line 122
    return-void
.end method

.method protected onSuccessfulUpload()V
    .locals 0

    .line 101
    return-void
.end method

.method public final run()V
    .locals 9

    .line 127
    new-instance v0, Lnet/gotev/uploadservice/UploadInfo;

    iget-object v1, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Lnet/gotev/uploadservice/UploadInfo;-><init>(Ljava/lang/String;)V

    invoke-direct {p0, v0}, Lnet/gotev/uploadservice/UploadTask;->createNotification(Lnet/gotev/uploadservice/UploadInfo;)V

    .line 129
    const/4 v0, 0x0

    iput v0, p0, Lnet/gotev/uploadservice/UploadTask;->attempts:I

    .line 131
    sget v0, Lnet/gotev/uploadservice/UploadService;->INITIAL_RETRY_WAIT_TIME:I

    .line 133
    .local v0, "errorDelay":I
    :goto_0
    iget v1, p0, Lnet/gotev/uploadservice/UploadTask;->attempts:I

    iget-object v2, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getMaxRetries()I

    move-result v2

    if-gt v1, v2, :cond_4

    iget-boolean v1, p0, Lnet/gotev/uploadservice/UploadTask;->shouldContinue:Z

    if-eqz v1, :cond_4

    .line 134
    iget v1, p0, Lnet/gotev/uploadservice/UploadTask;->attempts:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Lnet/gotev/uploadservice/UploadTask;->attempts:I

    .line 137
    :try_start_0
    invoke-virtual {p0}, Lnet/gotev/uploadservice/UploadTask;->upload()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 138
    goto/16 :goto_4

    .line 140
    :catch_0
    move-exception v1

    .line 141
    .local v1, "exc":Ljava/lang/Exception;
    iget-boolean v2, p0, Lnet/gotev/uploadservice/UploadTask;->shouldContinue:Z

    if-nez v2, :cond_0

    .line 142
    goto :goto_4

    .line 143
    :cond_0
    iget v2, p0, Lnet/gotev/uploadservice/UploadTask;->attempts:I

    iget-object v3, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v3}, Lnet/gotev/uploadservice/UploadTaskParameters;->getMaxRetries()I

    move-result v3

    if-le v2, v3, :cond_1

    .line 144
    invoke-direct {p0, v1}, Lnet/gotev/uploadservice/UploadTask;->broadcastError(Ljava/lang/Exception;)V

    goto :goto_3

    .line 146
    :cond_1
    sget-object v2, Lnet/gotev/uploadservice/UploadTask;->LOG_TAG:Ljava/lang/String;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Error in uploadId "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v4, p0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v4}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, " on attempt "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v4, p0, Lnet/gotev/uploadservice/UploadTask;->attempts:I

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v4, ". Waiting "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    div-int/lit16 v4, v0, 0x3e8

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v4, "s before next attempt. "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-static {v2, v3, v1}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 150
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v2

    .line 152
    .local v2, "beforeSleepTs":J
    :goto_1
    iget-boolean v4, p0, Lnet/gotev/uploadservice/UploadTask;->shouldContinue:Z

    if-eqz v4, :cond_2

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v4

    int-to-long v6, v0

    add-long/2addr v6, v2

    cmp-long v8, v4, v6

    if-gez v8, :cond_2

    .line 154
    const-wide/16 v4, 0x7d0

    :try_start_1
    invoke-static {v4, v5}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 155
    :goto_2
    goto :goto_1

    :catchall_0
    move-exception v4

    goto :goto_2

    .line 158
    :cond_2
    sget v4, Lnet/gotev/uploadservice/UploadService;->BACKOFF_MULTIPLIER:I

    mul-int v0, v0, v4

    .line 159
    sget v4, Lnet/gotev/uploadservice/UploadService;->MAX_RETRY_WAIT_TIME:I

    if-le v0, v4, :cond_3

    .line 160
    sget v0, Lnet/gotev/uploadservice/UploadService;->MAX_RETRY_WAIT_TIME:I

    .line 163
    .end local v1    # "exc":Ljava/lang/Exception;
    .end local v2    # "beforeSleepTs":J
    :cond_3
    :goto_3
    goto/16 :goto_0

    .line 166
    :cond_4
    :goto_4
    iget-boolean v1, p0, Lnet/gotev/uploadservice/UploadTask;->shouldContinue:Z

    if-nez v1, :cond_5

    .line 167
    invoke-virtual {p0}, Lnet/gotev/uploadservice/UploadTask;->broadcastCancelled()V

    .line 169
    :cond_5
    return-void
.end method

.method protected final setLastProgressNotificationTime(J)Lnet/gotev/uploadservice/UploadTask;
    .locals 0
    .param p1, "lastProgressNotificationTime"    # J

    .line 178
    iput-wide p1, p0, Lnet/gotev/uploadservice/UploadTask;->lastProgressNotificationTime:J

    .line 179
    return-object p0
.end method

.method protected final setNotificationId(I)Lnet/gotev/uploadservice/UploadTask;
    .locals 0
    .param p1, "notificationId"    # I

    .line 190
    iput p1, p0, Lnet/gotev/uploadservice/UploadTask;->notificationId:I

    .line 191
    return-object p0
.end method

.method protected abstract upload()V
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation
.end method
