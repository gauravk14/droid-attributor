.class public final Lnet/gotev/uploadservice/UploadService;
.super Landroid/app/Service;
.source "UploadService.java"


# static fields
.field private static final ACTION_UPLOAD_SUFFIX:Ljava/lang/String; = ".uploadservice.action.upload"

.field public static BACKOFF_MULTIPLIER:I = 0x0

.field private static final BROADCAST_ACTION_SUFFIX:Ljava/lang/String; = ".uploadservice.broadcast.status"

.field public static BUFFER_SIZE:I = 0x0

.field public static EXECUTE_IN_FOREGROUND:Z = false

.field public static HTTP_STACK:Lnet/gotev/uploadservice/http/HttpStack; = null

.field public static INITIAL_RETRY_WAIT_TIME:I = 0x0

.field public static KEEP_ALIVE_TIME_IN_SECONDS:I = 0x0

.field public static MAX_RETRY_WAIT_TIME:I = 0x0

.field public static NAMESPACE:Ljava/lang/String; = null

.field protected static final PARAM_BROADCAST_DATA:Ljava/lang/String; = "broadcastData"

.field protected static final PARAM_TASK_CLASS:Ljava/lang/String; = "taskClass"

.field protected static final PARAM_TASK_PARAMETERS:Ljava/lang/String; = "taskParameters"

.field protected static final PROGRESS_REPORT_INTERVAL:J = 0xa6L

.field private static final TAG:Ljava/lang/String;

.field protected static final UPLOAD_NOTIFICATION_BASE_ID:I = 0x4d2

.field public static UPLOAD_POOL_SIZE:I

.field private static volatile foregroundUploadId:Ljava/lang/String;

.field private static final uploadDelegates:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lnet/gotev/uploadservice/UploadStatusDelegate;",
            ">;"
        }
    .end annotation
.end field

.field private static final uploadTasksMap:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lnet/gotev/uploadservice/UploadTask;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private notificationIncrementalId:I

.field private final uploadTasksQueue:Ljava/util/concurrent/BlockingQueue;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/BlockingQueue<",
            "Ljava/lang/Runnable;",
            ">;"
        }
    .end annotation
.end field

.field private uploadThreadPool:Ljava/util/concurrent/ThreadPoolExecutor;

.field private wakeLock:Landroid/os/PowerManager$WakeLock;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 34
    const-class v0, Lnet/gotev/uploadservice/UploadService;

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    .line 40
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Runtime;->availableProcessors()I

    move-result v0

    sput v0, Lnet/gotev/uploadservice/UploadService;->UPLOAD_POOL_SIZE:I

    .line 46
    const/4 v0, 0x1

    sput v0, Lnet/gotev/uploadservice/UploadService;->KEEP_ALIVE_TIME_IN_SECONDS:I

    .line 56
    sput-boolean v0, Lnet/gotev/uploadservice/UploadService;->EXECUTE_IN_FOREGROUND:Z

    .line 62
    const-string v0, "net.gotev"

    sput-object v0, Lnet/gotev/uploadservice/UploadService;->NAMESPACE:Ljava/lang/String;

    .line 68
    new-instance v0, Lnet/gotev/uploadservice/http/impl/HurlStack;

    invoke-direct {v0}, Lnet/gotev/uploadservice/http/impl/HurlStack;-><init>()V

    sput-object v0, Lnet/gotev/uploadservice/UploadService;->HTTP_STACK:Lnet/gotev/uploadservice/http/HttpStack;

    .line 73
    const/16 v0, 0x1000

    sput v0, Lnet/gotev/uploadservice/UploadService;->BUFFER_SIZE:I

    .line 80
    const/16 v0, 0x3e8

    sput v0, Lnet/gotev/uploadservice/UploadService;->INITIAL_RETRY_WAIT_TIME:I

    .line 88
    const/16 v0, 0xa

    sput v0, Lnet/gotev/uploadservice/UploadService;->BACKOFF_MULTIPLIER:I

    .line 96
    const v0, 0x927c0

    sput v0, Lnet/gotev/uploadservice/UploadService;->MAX_RETRY_WAIT_TIME:I

    .line 120
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    sput-object v0, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    .line 121
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    sput-object v0, Lnet/gotev/uploadservice/UploadService;->uploadDelegates:Ljava/util/Map;

    .line 123
    const/4 v0, 0x0

    sput-object v0, Lnet/gotev/uploadservice/UploadService;->foregroundUploadId:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 32
    invoke-direct {p0}, Landroid/app/Service;-><init>()V

    .line 119
    const/4 v0, 0x0

    iput v0, p0, Lnet/gotev/uploadservice/UploadService;->notificationIncrementalId:I

    .line 122
    new-instance v0, Ljava/util/concurrent/LinkedBlockingQueue;

    invoke-direct {v0}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    iput-object v0, p0, Lnet/gotev/uploadservice/UploadService;->uploadTasksQueue:Ljava/util/concurrent/BlockingQueue;

    return-void
.end method

.method protected static getActionBroadcast()Ljava/lang/String;
    .locals 2

    .line 131
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v1, Lnet/gotev/uploadservice/UploadService;->NAMESPACE:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ".uploadservice.broadcast.status"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method protected static getActionUpload()Ljava/lang/String;
    .locals 2

    .line 127
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v1, Lnet/gotev/uploadservice/UploadService;->NAMESPACE:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ".uploadservice.action.upload"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public static declared-synchronized getTaskList()Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    const-class v0, Lnet/gotev/uploadservice/UploadService;

    monitor-enter v0

    .line 152
    :try_start_0
    sget-object v1, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    .line 153
    new-instance v1, Ljava/util/ArrayList;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .local v1, "tasks":Ljava/util/List;, "Ljava/util/List<Ljava/lang/String;>;"
    goto :goto_0

    .line 155
    .end local v1    # "tasks":Ljava/util/List;, "Ljava/util/List<Ljava/lang/String;>;"
    :cond_0
    new-instance v1, Ljava/util/ArrayList;

    sget-object v2, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    invoke-interface {v2}, Ljava/util/Map;->size()I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 156
    .restart local v1    # "tasks":Ljava/util/List;, "Ljava/util/List<Ljava/lang/String;>;"
    sget-object v2, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    invoke-interface {v2}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object v2

    invoke-interface {v1, v2}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 159
    :goto_0
    monitor-exit v0

    return-object v1

    .line 151
    .end local v1    # "tasks":Ljava/util/List;, "Ljava/util/List<Ljava/lang/String;>;"
    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1
.end method

.method protected static getUploadStatusDelegate(Ljava/lang/String;)Lnet/gotev/uploadservice/UploadStatusDelegate;
    .locals 1
    .param p0, "uploadId"    # Ljava/lang/String;

    .line 368
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->uploadDelegates:Ljava/util/Map;

    invoke-interface {v0, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/UploadStatusDelegate;

    return-object v0
.end method

.method protected static setUploadStatusDelegate(Ljava/lang/String;Lnet/gotev/uploadservice/UploadStatusDelegate;)V
    .locals 1
    .param p0, "uploadId"    # Ljava/lang/String;
    .param p1, "delegate"    # Lnet/gotev/uploadservice/UploadStatusDelegate;

    .line 355
    if-nez p1, :cond_0

    .line 356
    return-void

    .line 358
    :cond_0
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->uploadDelegates:Ljava/util/Map;

    invoke-interface {v0, p0, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 359
    return-void
.end method

.method private shutdownIfThereArentAnyActiveTasks()I
    .locals 1

    .line 244
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 245
    invoke-virtual {p0}, Lnet/gotev/uploadservice/UploadService;->stopSelf()V

    .line 246
    const/4 v0, 0x2

    return v0

    .line 249
    :cond_0
    const/4 v0, 0x1

    return v0
.end method

.method public static declared-synchronized stopAllUploads()V
    .locals 4

    const-class v0, Lnet/gotev/uploadservice/UploadService;

    monitor-enter v0

    .line 166
    :try_start_0
    sget-object v1, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_0

    .line 167
    monitor-exit v0

    return-void

    .line 171
    :cond_0
    :try_start_1
    sget-object v1, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    invoke-interface {v1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v1

    .line 173
    .local v1, "iterator":Ljava/util/Iterator;, "Ljava/util/Iterator<Ljava/lang/String;>;"
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    .line 174
    sget-object v2, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    invoke-interface {v2, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lnet/gotev/uploadservice/UploadTask;

    .line 175
    .local v2, "taskToCancel":Lnet/gotev/uploadservice/UploadTask;
    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTask;->cancel()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 176
    .end local v2    # "taskToCancel":Lnet/gotev/uploadservice/UploadTask;
    goto :goto_0

    .line 177
    :cond_1
    monitor-exit v0

    return-void

    .line 165
    .end local v1    # "iterator":Ljava/util/Iterator;, "Ljava/util/Iterator<Ljava/lang/String;>;"
    :catchall_0
    move-exception v1

    monitor-exit v0

    goto :goto_2

    :goto_1
    throw v1

    :goto_2
    goto :goto_1
.end method

.method public static declared-synchronized stopUpload(Ljava/lang/String;)V
    .locals 2
    .param p0, "uploadId"    # Ljava/lang/String;

    const-class v0, Lnet/gotev/uploadservice/UploadService;

    monitor-enter v0

    .line 139
    :try_start_0
    sget-object v1, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    invoke-interface {v1, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lnet/gotev/uploadservice/UploadTask;

    .line 140
    .local v1, "removedTask":Lnet/gotev/uploadservice/UploadTask;
    if-eqz v1, :cond_0

    .line 141
    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTask;->cancel()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 143
    :cond_0
    monitor-exit v0

    return-void

    .line 138
    .end local v1    # "removedTask":Lnet/gotev/uploadservice/UploadTask;
    .end local p0    # "uploadId":Ljava/lang/String;
    :catchall_0
    move-exception p0

    monitor-exit v0

    throw p0
.end method


# virtual methods
.method getTask(Landroid/content/Intent;)Lnet/gotev/uploadservice/UploadTask;
    .locals 6
    .param p1, "intent"    # Landroid/content/Intent;

    .line 279
    const-string v0, "taskClass"

    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 281
    .local v0, "taskClass":Ljava/lang/String;
    if-nez v0, :cond_0

    .line 282
    const/4 v1, 0x0

    return-object v1

    .line 285
    :cond_0
    const/4 v1, 0x0

    .line 288
    .local v1, "uploadTask":Lnet/gotev/uploadservice/UploadTask;
    :try_start_0
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v2

    .line 290
    .local v2, "task":Ljava/lang/Class;, "Ljava/lang/Class<*>;"
    const-class v3, Lnet/gotev/uploadservice/UploadTask;

    invoke-virtual {v3, v2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-eqz v3, :cond_1

    .line 291
    const-class v3, Lnet/gotev/uploadservice/UploadTask;

    invoke-virtual {v2}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/Class;->cast(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lnet/gotev/uploadservice/UploadTask;

    move-object v1, v3

    .line 292
    invoke-virtual {v1, p0, p1}, Lnet/gotev/uploadservice/UploadTask;->init(Lnet/gotev/uploadservice/UploadService;Landroid/content/Intent;)V

    goto :goto_0

    .line 294
    :cond_1
    sget-object v3, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, " does not extend UploadTask!"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v3, v4}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;)V

    .line 297
    :goto_0
    sget-object v3, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "Successfully created new task with class: "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v3, v4}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 301
    .end local v2    # "task":Ljava/lang/Class;, "Ljava/lang/Class<*>;"
    goto :goto_1

    .line 299
    :catch_0
    move-exception v2

    .line 300
    .local v2, "exc":Ljava/lang/Exception;
    sget-object v3, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    const-string v4, "Error while instantiating new task"

    invoke-static {v3, v4, v2}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 303
    .end local v2    # "exc":Ljava/lang/Exception;
    :goto_1
    return-object v1
.end method

.method protected declared-synchronized holdForegroundNotification(Ljava/lang/String;Landroid/app/Notification;)Z
    .locals 4
    .param p1, "uploadId"    # Ljava/lang/String;
    .param p2, "notification"    # Landroid/app/Notification;

    monitor-enter p0

    .line 312
    :try_start_0
    sget-boolean v0, Lnet/gotev/uploadservice/UploadService;->EXECUTE_IN_FOREGROUND:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    monitor-exit p0

    return v1

    .line 314
    :cond_0
    :try_start_1
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->foregroundUploadId:Ljava/lang/String;

    if-nez v0, :cond_1

    .line 315
    sput-object p1, Lnet/gotev/uploadservice/UploadService;->foregroundUploadId:Ljava/lang/String;

    .line 316
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, " now holds the foreground notification"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v0, v2}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 319
    .end local p0    # "this":Lnet/gotev/uploadservice/UploadService;
    :cond_1
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->foregroundUploadId:Ljava/lang/String;

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    .line 320
    const/16 v0, 0x4d2

    invoke-virtual {p0, v0, p2}, Lnet/gotev/uploadservice/UploadService;->startForeground(ILandroid/app/Notification;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 321
    const/4 v0, 0x1

    monitor-exit p0

    return v0

    .line 324
    :cond_2
    monitor-exit p0

    return v1

    .line 311
    .end local p1    # "uploadId":Ljava/lang/String;
    .end local p2    # "notification":Landroid/app/Notification;
    :catchall_0
    move-exception p1

    monitor-exit p0

    throw p1
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 1
    .param p1, "intent"    # Landroid/content/Intent;

    .line 205
    const/4 v0, 0x0

    return-object v0
.end method

.method public onCreate()V
    .locals 9

    .line 181
    invoke-super {p0}, Landroid/app/Service;->onCreate()V

    .line 183
    const-string v0, "power"

    invoke-virtual {p0, v0}, Lnet/gotev/uploadservice/UploadService;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/os/PowerManager;

    .line 184
    .local v0, "pm":Landroid/os/PowerManager;
    sget-object v1, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    const/4 v2, 0x1

    invoke-virtual {v0, v2, v1}, Landroid/os/PowerManager;->newWakeLock(ILjava/lang/String;)Landroid/os/PowerManager$WakeLock;

    move-result-object v1

    iput-object v1, p0, Lnet/gotev/uploadservice/UploadService;->wakeLock:Landroid/os/PowerManager$WakeLock;

    .line 185
    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Landroid/os/PowerManager$WakeLock;->setReferenceCounted(Z)V

    .line 187
    iget-object v1, p0, Lnet/gotev/uploadservice/UploadService;->wakeLock:Landroid/os/PowerManager$WakeLock;

    invoke-virtual {v1}, Landroid/os/PowerManager$WakeLock;->isHeld()Z

    move-result v1

    if-nez v1, :cond_0

    .line 188
    iget-object v1, p0, Lnet/gotev/uploadservice/UploadService;->wakeLock:Landroid/os/PowerManager$WakeLock;

    invoke-virtual {v1}, Landroid/os/PowerManager$WakeLock;->acquire()V

    .line 190
    :cond_0
    sget v1, Lnet/gotev/uploadservice/UploadService;->UPLOAD_POOL_SIZE:I

    if-gtz v1, :cond_1

    .line 191
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Runtime;->availableProcessors()I

    move-result v1

    sput v1, Lnet/gotev/uploadservice/UploadService;->UPLOAD_POOL_SIZE:I

    .line 195
    :cond_1
    new-instance v1, Ljava/util/concurrent/ThreadPoolExecutor;

    sget v4, Lnet/gotev/uploadservice/UploadService;->UPLOAD_POOL_SIZE:I

    sget v2, Lnet/gotev/uploadservice/UploadService;->KEEP_ALIVE_TIME_IN_SECONDS:I

    int-to-long v5, v2

    sget-object v7, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    iget-object v8, p0, Lnet/gotev/uploadservice/UploadService;->uploadTasksQueue:Ljava/util/concurrent/BlockingQueue;

    move-object v2, v1

    move v3, v4

    invoke-direct/range {v2 .. v8}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;)V

    iput-object v1, p0, Lnet/gotev/uploadservice/UploadService;->uploadThreadPool:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 201
    return-void
.end method

.method public onDestroy()V
    .locals 2

    .line 254
    invoke-super {p0}, Landroid/app/Service;->onDestroy()V

    .line 256
    invoke-static {}, Lnet/gotev/uploadservice/UploadService;->stopAllUploads()V

    .line 257
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadService;->uploadThreadPool:Ljava/util/concurrent/ThreadPoolExecutor;

    invoke-virtual {v0}, Ljava/util/concurrent/ThreadPoolExecutor;->shutdown()V

    .line 259
    sget-boolean v0, Lnet/gotev/uploadservice/UploadService;->EXECUTE_IN_FOREGROUND:Z

    if-eqz v0, :cond_0

    .line 260
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    const-string v1, "Stopping foreground execution"

    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 261
    const/4 v0, 0x1

    invoke-virtual {p0, v0}, Lnet/gotev/uploadservice/UploadService;->stopForeground(Z)V

    .line 264
    :cond_0
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadService;->wakeLock:Landroid/os/PowerManager$WakeLock;

    invoke-virtual {v0}, Landroid/os/PowerManager$WakeLock;->isHeld()Z

    move-result v0

    if-eqz v0, :cond_1

    .line 265
    iget-object v0, p0, Lnet/gotev/uploadservice/UploadService;->wakeLock:Landroid/os/PowerManager$WakeLock;

    invoke-virtual {v0}, Landroid/os/PowerManager$WakeLock;->release()V

    .line 267
    :cond_1
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    invoke-interface {v0}, Ljava/util/Map;->clear()V

    .line 268
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->uploadDelegates:Ljava/util/Map;

    invoke-interface {v0}, Ljava/util/Map;->clear()V

    .line 270
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    const-string v1, "UploadService destroyed"

    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 271
    return-void
.end method

.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 7
    .param p1, "intent"    # Landroid/content/Intent;
    .param p2, "flags"    # I
    .param p3, "startId"    # I

    .line 210
    if-eqz p1, :cond_4

    invoke-static {}, Lnet/gotev/uploadservice/UploadService;->getActionUpload()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    goto/16 :goto_1

    .line 214
    :cond_0
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v1

    const/4 v2, 0x4

    new-array v2, v2, [Ljava/lang/Object;

    const/4 v3, 0x0

    sget-object v4, Lnet/gotev/uploadservice/UploadService;->NAMESPACE:Ljava/lang/String;

    aput-object v4, v2, v3

    sget v3, Lnet/gotev/uploadservice/UploadService;->UPLOAD_POOL_SIZE:I

    .line 216
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    const/4 v4, 0x1

    aput-object v3, v2, v4

    sget v3, Lnet/gotev/uploadservice/UploadService;->KEEP_ALIVE_TIME_IN_SECONDS:I

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    const/4 v5, 0x2

    aput-object v3, v2, v5

    const/4 v3, 0x3

    sget-boolean v6, Lnet/gotev/uploadservice/UploadService;->EXECUTE_IN_FOREGROUND:Z

    if-eqz v6, :cond_1

    const-string v6, "enabled"

    goto :goto_0

    :cond_1
    const-string v6, "disabled"

    :goto_0
    aput-object v6, v2, v3

    .line 214
    const-string v3, "Starting service with namespace: %s, upload pool size: %d, %ds idle thread keep alive time. Foreground execution is %s"

    invoke-static {v1, v3, v2}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Lnet/gotev/uploadservice/Logger;->info(Ljava/lang/String;Ljava/lang/String;)V

    .line 219
    invoke-virtual {p0, p1}, Lnet/gotev/uploadservice/UploadService;->getTask(Landroid/content/Intent;)Lnet/gotev/uploadservice/UploadTask;

    move-result-object v0

    .line 221
    .local v0, "currentTask":Lnet/gotev/uploadservice/UploadTask;
    if-nez v0, :cond_2

    .line 222
    invoke-direct {p0}, Lnet/gotev/uploadservice/UploadService;->shutdownIfThereArentAnyActiveTasks()I

    move-result v1

    return v1

    .line 225
    :cond_2
    sget-object v1, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    iget-object v2, v0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v2

    invoke-interface {v1, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    .line 226
    sget-object v1, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Preventing upload with id: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v3, v0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v3}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, " to be uploaded twice! Please check your code and fix it!"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Lnet/gotev/uploadservice/Logger;->error(Ljava/lang/String;Ljava/lang/String;)V

    .line 228
    invoke-direct {p0}, Lnet/gotev/uploadservice/UploadService;->shutdownIfThereArentAnyActiveTasks()I

    move-result v1

    return v1

    .line 233
    :cond_3
    iget v1, p0, Lnet/gotev/uploadservice/UploadService;->notificationIncrementalId:I

    add-int/2addr v1, v5

    iput v1, p0, Lnet/gotev/uploadservice/UploadService;->notificationIncrementalId:I

    .line 234
    const-wide/16 v1, 0x0

    invoke-virtual {v0, v1, v2}, Lnet/gotev/uploadservice/UploadTask;->setLastProgressNotificationTime(J)Lnet/gotev/uploadservice/UploadTask;

    move-result-object v1

    iget v2, p0, Lnet/gotev/uploadservice/UploadService;->notificationIncrementalId:I

    add-int/lit16 v2, v2, 0x4d2

    .line 235
    invoke-virtual {v1, v2}, Lnet/gotev/uploadservice/UploadTask;->setNotificationId(I)Lnet/gotev/uploadservice/UploadTask;

    .line 237
    sget-object v1, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    iget-object v2, v0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v2}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v2

    invoke-interface {v1, v2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 238
    iget-object v1, p0, Lnet/gotev/uploadservice/UploadService;->uploadThreadPool:Ljava/util/concurrent/ThreadPoolExecutor;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 240
    return v4

    .line 211
    .end local v0    # "currentTask":Lnet/gotev/uploadservice/UploadTask;
    :cond_4
    :goto_1
    invoke-direct {p0}, Lnet/gotev/uploadservice/UploadService;->shutdownIfThereArentAnyActiveTasks()I

    move-result v0

    return v0
.end method

.method protected declared-synchronized taskCompleted(Ljava/lang/String;)V
    .locals 4
    .param p1, "uploadId"    # Ljava/lang/String;

    monitor-enter p0

    .line 333
    :try_start_0
    sget-object v0, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lnet/gotev/uploadservice/UploadTask;

    .line 334
    .local v0, "task":Lnet/gotev/uploadservice/UploadTask;
    sget-object v1, Lnet/gotev/uploadservice/UploadService;->uploadDelegates:Ljava/util/Map;

    invoke-interface {v1, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 337
    sget-boolean v1, Lnet/gotev/uploadservice/UploadService;->EXECUTE_IN_FOREGROUND:Z

    if-eqz v1, :cond_0

    if-eqz v0, :cond_0

    iget-object v1, v0, Lnet/gotev/uploadservice/UploadTask;->params:Lnet/gotev/uploadservice/UploadTaskParameters;

    invoke-virtual {v1}, Lnet/gotev/uploadservice/UploadTaskParameters;->getId()Ljava/lang/String;

    move-result-object v1

    sget-object v2, Lnet/gotev/uploadservice/UploadService;->foregroundUploadId:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    .line 338
    sget-object v1, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, " now un-holded the foreground notification"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 339
    const/4 v1, 0x0

    sput-object v1, Lnet/gotev/uploadservice/UploadService;->foregroundUploadId:Ljava/lang/String;

    .line 342
    .end local p0    # "this":Lnet/gotev/uploadservice/UploadService;
    :cond_0
    sget-boolean v1, Lnet/gotev/uploadservice/UploadService;->EXECUTE_IN_FOREGROUND:Z

    if-eqz v1, :cond_1

    sget-object v1, Lnet/gotev/uploadservice/UploadService;->uploadTasksMap:Ljava/util/Map;

    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_1

    .line 343
    sget-object v1, Lnet/gotev/uploadservice/UploadService;->TAG:Ljava/lang/String;

    const-string v2, "All tasks completed, stopping foreground execution"

    invoke-static {v1, v2}, Lnet/gotev/uploadservice/Logger;->debug(Ljava/lang/String;Ljava/lang/String;)V

    .line 344
    const/4 v1, 0x1

    invoke-virtual {p0, v1}, Lnet/gotev/uploadservice/UploadService;->stopForeground(Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 346
    :cond_1
    monitor-exit p0

    return-void

    .line 332
    .end local v0    # "task":Lnet/gotev/uploadservice/UploadTask;
    .end local p1    # "uploadId":Ljava/lang/String;
    :catchall_0
    move-exception p1

    monitor-exit p0

    throw p1
.end method
